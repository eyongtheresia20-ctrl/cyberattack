from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, AuditLog, AnalysisRecord, Incident, IncidentReport
from app.api.v1.auth import get_current_user, find_user_by_id

router = APIRouter(prefix="/users", tags=["User Management"])

class RoleUpdateRequest(BaseModel):
    new_role: str # UTILISATEUR_STANDARD or ENQUETEUR

@router.get("", response_model=dict)
def list_users(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")
    
    # Auto-sync with MongoDB
    try:
        from app.db.mongodb import mongo_collections
        mongo_enq_emails = set(u.get("email") for u in mongo_collections.investigators.find({}, {"email": 1}))
        for std in db.query(UtilisateurStandard).all():
            if std.email in mongo_enq_emails:
                new_enq = Enqueteur(
                    id=std.id,
                    nom=std.nom,
                    prenom=std.prenom,
                    email=std.email,
                    hashed_password=std.hashed_password,
                    role="ENQUETEUR",
                    badge_number=f"SOC-{std.id[:8]}",
                    is_active=std.is_active
                )
                db.delete(std)
                db.add(new_enq)
                db.commit()
    except Exception as _e:
        pass

    stds = db.query(UtilisateurStandard).all()
    enqs = db.query(Enqueteur).all()
    adms = db.query(Administrateur).all()
    
    user_list = []
    for u in stds:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "utilisateurs_standards", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    for u in enqs:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "enqueteurs", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    for u in adms:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "administrateurs", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
        
    return {"users": user_list, "total": len(user_list)}

@router.patch("/{user_id}/role", response_model=dict)
def update_user_role(
    user_id: str,
    req: RoleUpdateRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")
    
    target_user = find_user_by_id(user_id, db)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")
    
    # ADMIN SAFEGUARD RULE: An Admin CANNOT edit, demote, or delete another Admin account
    if target_user.role == "ADMINISTRATEUR" or isinstance(target_user, Administrateur):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Protégé : Les comptes Administrateur ne peuvent pas être modifiés ou rétrogradés."
        )
        
    if req.new_role not in ["UTILISATEUR_STANDARD", "ENQUETEUR"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rôle invalide. Seuls UTILISATEUR_STANDARD et ENQUETEUR sont attribuables."
        )
        
    old_role = target_user.role
    
    # If role changed, move record between distinct tables
    if req.new_role == "ENQUETEUR" and not isinstance(target_user, Enqueteur):
        new_user = Enqueteur(
            id=target_user.id,
            nom=target_user.nom,
            prenom=target_user.prenom,
            email=target_user.email,
            hashed_password=target_user.hashed_password,
            role="ENQUETEUR",
            badge_number=f"SOC-{target_user.id[:8]}"
        )
        db.delete(target_user)
        db.add(new_user)
        target_user = new_user
    elif req.new_role == "UTILISATEUR_STANDARD" and not isinstance(target_user, UtilisateurStandard):
        new_user = UtilisateurStandard(
            id=target_user.id,
            nom=target_user.nom,
            prenom=target_user.prenom,
            email=target_user.email,
            hashed_password=target_user.hashed_password,
            role="UTILISATEUR_STANDARD"
        )
        db.delete(target_user)
        db.add(new_user)
        target_user = new_user

    audit = AuditLog(
        actor=f"{current_user.prenom} {current_user.nom}",
        action="UPDATE_USER_ROLE",
        target=target_user.email,
        details=f"Changement de rôle : {old_role} -> {req.new_role}"
    )
    db.add(audit)
    db.commit()

    # Sync to MongoDB
    try:
        from app.db.mongodb import mongo_collections, log_mongo_audit
        if req.new_role == "ENQUETEUR":
            mongo_collections.users.delete_one({"email": target_user.email})
            inv_doc = {
                "id": str(target_user.id),
                "nom": target_user.nom,
                "prenom": target_user.prenom,
                "email": target_user.email,
                "hashed_password": target_user.hashed_password,
                "password_raw": getattr(target_user, "password_raw", "phishguard2026"),
                "role": "ENQUETEUR",
                "badge_number": f"SOC-{str(target_user.id)[:8]}",
                "clearance_level": "LEVEL_2_SOC",
                "cases_resolved": 0,
                "scan_count": getattr(target_user, "scan_count", 0) or 0,
                "report_count": getattr(target_user, "report_count", 0) or 0,
                "is_active": target_user.is_active,
                "created_at": getattr(target_user, "created_at", datetime.now(timezone.utc)),
                "last_login": getattr(target_user, "last_login", datetime.now(timezone.utc))
            }
            mongo_collections.investigators.insert_one(inv_doc)
        else:
            mongo_collections.investigators.delete_one({"email": target_user.email})
            std_doc = {
                "id": str(target_user.id),
                "nom": target_user.nom,
                "prenom": target_user.prenom,
                "email": target_user.email,
                "hashed_password": target_user.hashed_password,
                "password_raw": getattr(target_user, "password_raw", "User123!"),
                "role": "UTILISATEUR_STANDARD",
                "scan_count": getattr(target_user, "scan_count", 0) or 0,
                "report_count": getattr(target_user, "report_count", 0) or 0,
                "is_active": target_user.is_active,
                "preferred_language": "fr",
                "created_at": getattr(target_user, "created_at", datetime.now(timezone.utc)),
                "last_login": getattr(target_user, "last_login", datetime.now(timezone.utc))
            }
            mongo_collections.users.insert_one(std_doc)

        log_mongo_audit(
            actor=f"{current_user.prenom} {current_user.nom}",
            action="UPDATE_USER_ROLE",
            target=target_user.email,
            details=f"Changement de rôle : {old_role} -> {req.new_role}"
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Role: {_me}")
    
    return {
        "message": f"Rôle mis à jour avec succès en {target_user.role}",
        "user": {
            "id": target_user.id,
            "email": target_user.email,
            "role": target_user.role,
            "table": target_user.__tablename__
        }
    }

class StatusUpdateRequest(BaseModel):
    is_active: bool

@router.patch("/{user_id}/status", response_model=dict)
def toggle_user_status(
    user_id: str,
    req: StatusUpdateRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")

    target_user = find_user_by_id(user_id, db)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")

    if target_user.role == "ADMINISTRATEUR" or isinstance(target_user, Administrateur):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Protégé : Les comptes Administrateur ne peuvent pas être désactivés.")

    target_user.is_active = req.is_active
    audit = AuditLog(
        actor=f"{current_user.prenom} {current_user.nom}",
        action="UPDATE_USER_STATUS",
        target=target_user.email,
        details=f"Statut utilisateur mis à jour : {'Activé / Approuvé' if req.is_active else 'Désactivé'}"
    )
    db.add(audit)
    db.commit()

    # Sync to MongoDB
    try:
        from app.db.mongodb import mongo_collections, log_mongo_audit
        for col in [mongo_collections.users, mongo_collections.investigators]:
            col.update_one({"id": str(user_id)}, {"$set": {"is_active": req.is_active}})
        log_mongo_audit(
            actor=f"{current_user.prenom} {current_user.nom}",
            action="UPDATE_USER_STATUS",
            target=target_user.email,
            details=f"Statut utilisateur mis à jour : {'Activé / Approuvé' if req.is_active else 'Désactivé'}"
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Status: {_me}")

    return {"success": True, "message": f"Statut de {target_user.email} mis à jour : {'Activé' if req.is_active else 'Désactivé'}", "is_active": target_user.is_active}

@router.delete("/{user_id}", response_model=dict)
def delete_user(
    user_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")

    target_user = find_user_by_id(user_id, db)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")

    if target_user.role == "ADMINISTRATEUR" or isinstance(target_user, Administrateur):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Protégé : Les comptes Administrateur ne peuvent pas être supprimés.")

    target_email = target_user.email
    db.delete(target_user)
    audit = AuditLog(
        actor=f"{current_user.prenom} {current_user.nom}",
        action="DELETE_USER",
        target=target_email,
        details="Suppression définitive du compte par l'Administrateur"
    )
    db.add(audit)
    db.commit()

    # Sync to MongoDB
    try:
        from app.db.mongodb import mongo_collections, log_mongo_audit
        for col in [mongo_collections.users, mongo_collections.investigators]:
            col.delete_one({"id": str(user_id)})
        log_mongo_audit(
            actor=f"{current_user.prenom} {current_user.nom}",
            action="DELETE_USER",
            target=target_email,
            details="Suppression définitive du compte par l'Administrateur"
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Delete: {_me}")

    return {"success": True, "message": f"Compte {target_email} supprimé avec succès."}

def to_utc_iso(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        if not dt.endswith("Z") and not ("+" in dt[10:] or "-" in dt[10:]):
            return dt + "Z"
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

@router.get("/activity-logs", response_model=dict)
def get_user_activity_logs(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")

    # ── Build a full lookup: user_id -> (name, role, email) across all account roles from MongoDB primary
    user_id_map = {}
    try:
        from app.db.mongodb import mongo_collections
        for u in mongo_collections.users.find():
            user_id_map[str(u.get("id"))] = {"name": f"{u.get('prenom', '')} {u.get('nom', '')}".strip() or "Alice Martin", "role": "Utilisateur Standard", "email": u.get("email")}
        for u in mongo_collections.investigators.find():
            user_id_map[str(u.get("id"))] = {"name": f"{u.get('prenom', '')} {u.get('nom', '')}".strip() or "Alex Vance", "role": "Enquêteur SOC", "email": u.get("email")}
        for u in mongo_collections.admins.find():
            user_id_map[str(u.get("id"))] = {"name": f"{u.get('prenom', '')} {u.get('nom', '')}".strip() or "System Admin", "role": "Administrateur", "email": u.get("email")}
    except Exception:
        pass

    # Fallback/merge lookup from SQL if needed
    for u in db.query(UtilisateurStandard).all():
        if str(u.id) not in user_id_map:
            user_id_map[str(u.id)] = {"name": f"{u.prenom} {u.nom}", "role": "Utilisateur Standard", "email": u.email}
    for u in db.query(Enqueteur).all():
        if str(u.id) not in user_id_map:
            user_id_map[str(u.id)] = {"name": f"{u.prenom} {u.nom}", "role": "Enquêteur SOC", "email": u.email}
    for u in db.query(Administrateur).all():
        if str(u.id) not in user_id_map:
            user_id_map[str(u.id)] = {"name": f"{u.prenom} {u.nom}", "role": "Administrateur", "email": u.email}

    # Retrieve logs directly from MongoDB primary
    logs = []
    records = []
    incidents = []
    try:
        from app.db.mongodb import mongo_collections
        m_logs = list(mongo_collections.audit_logs.find().sort("timestamp", -1).limit(150))
        for ml in m_logs:
            logs.append({
                "id": str(ml.get("id", ml.get("_id"))),
                "actor": ml.get("actor"),
                "action": ml.get("action"),
                "target": ml.get("target"),
                "details": ml.get("details"),
                "timestamp": ml.get("timestamp")
            })

        m_recs = list(mongo_collections.analyses.find({"is_deleted_by_user": {"$ne": True}}).sort("created_at", -1).limit(50))
        for mr in m_recs:
            records.append({
                "id": str(mr.get("id", mr.get("_id"))),
                "user_id": mr.get("user_id"),
                "analysis_code": mr.get("analysis_code"),
                "analysis_type": mr.get("analysis_type", "URL"),
                "target_content": mr.get("target_content", ""),
                "verdict": mr.get("verdict", "INCONNU"),
                "risk_score": mr.get("risk_score", 0.0),
                "risk_level": mr.get("risk_level", "LOW"),
                "ml_confidence": mr.get("ml_confidence", 98.4),
                "created_at": mr.get("created_at")
            })

        m_incs = list(mongo_collections.incidents.find().sort("created_at", -1).limit(50))
        for mi in m_incs:
            incidents.append({
                "id": str(mi.get("id", mi.get("_id"))),
                "incident_code": mi.get("incident_code"),
                "title": mi.get("title"),
                "status": mi.get("status", "NEW"),
                "severity": mi.get("severity", "LOW"),
                "source_ref_id": mi.get("source_ref_id"),
                "created_at": mi.get("created_at")
            })
    except Exception as _me:
        print(f"[MongoDB Logs Notice] Fallback to SQL: {_me}")

    # If MongoDB was empty or offline, fallback to SQL
    if not logs:
        for l in db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(150).all():
            logs.append({"id": l.id, "actor": l.actor, "action": l.action, "target": l.target, "details": l.details, "timestamp": l.timestamp})
    if not records:
        for r in db.query(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).limit(50).all():
            records.append({
                "id": r.id, "user_id": r.user_id, "analysis_code": r.analysis_code, "analysis_type": r.analysis_type,
                "target_content": r.target_content, "verdict": r.verdict, "risk_score": r.risk_score,
                "risk_level": r.risk_level, "ml_confidence": r.ml_confidence, "created_at": r.created_at
            })
    if not incidents:
        for inc in db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all():
            incidents.append({
                "id": inc.id, "incident_code": inc.incident_code, "title": inc.title,
                "status": inc.status, "severity": inc.severity, "source_ref_id": inc.source_ref_id,
                "created_at": inc.created_at
            })

    activations = []
    seen_login_times = {}

    # ── 1. AuditLog entries (logins, registrations, AI chats, security events)
    for l in logs:
        actor_str = l.get("actor") or "Utilisateur"
        ts_val = l.get("timestamp")
        ts_str = to_utc_iso(ts_val)
        
        # Deduplicate consecutive rapid login pings within 60s for clean readability
        action_name = l.get("action") or "ACTION"
        if action_name == "LOGIN":
            login_key = f"{actor_str}_{l.get('target')}"
            last_ts = seen_login_times.get(login_key)
            if last_ts and ts_val and abs((ts_val - last_ts).total_seconds()) < 60:
                continue
            if ts_val:
                seen_login_times[login_key] = ts_val

        # Clean details message if legacy table name exists
        details = l.get("details") or "Action sécurisée enregistrée"
        if "depuis la table" in details:
            details = "Connexion sécurisée au portail CyberGuard"
        elif "dans la table" in details:
            details = "Création de compte réussie"

        log_type = "SERVICE_ERROR" if action_name == "SERVICE_PIPELINE_ERROR" else ("AUDIT" if action_name in ("LOGIN", "REGISTER") else "SECURITY_ACTION")
        
        activations.append({
            "id": l.get("id"),
            "actor": actor_str,
            "type": log_type,
            "action": action_name,
            "target": l.get("target") or "-",
            "details": details,
            "timestamp": ts_str
        })

    # ── 2. Real Analysis scan records performed by actual users
    for r in records:
        if isinstance(r, dict):
            uid = str(r.get("user_id")) if r.get("user_id") else None
            atype = r.get("analysis_type", "URL")
            target = r.get("target_content", "")
            verdict = r.get("verdict", "INCONNU")
            rscore = r.get("risk_score")
            rlevel = r.get("risk_level")
            conf = r.get("ml_confidence")
            acode = r.get("analysis_code", "ANL-DEMO")
            rid = r.get("id")
            rcat = r.get("created_at")
        else:
            uid = str(r.user_id) if getattr(r, "user_id", None) else None
            atype = getattr(r, "analysis_type", "URL")
            target = getattr(r, "target_content", "")
            verdict = getattr(r, "verdict", "INCONNU")
            rscore = getattr(r, "risk_score", None)
            rlevel = getattr(r, "risk_level", None)
            conf = getattr(r, "ml_confidence", None)
            acode = getattr(r, "analysis_code", "ANL-DEMO")
            rid = getattr(r, "id", None)
            rcat = getattr(r, "created_at", None)

        user_info = user_id_map.get(uid) if uid else None
        actor_name = user_info["name"] if user_info else "Utilisateur"
        
        scan_type_clean = (atype or "URL").upper()
        if "AUDIT" in scan_type_clean:
            action_code = "AUDIT_DOMAINE"
        elif "EMAIL" in scan_type_clean:
            action_code = "SCAN_EMAIL"
        elif "SMS" in scan_type_clean or "MESSAGE" in scan_type_clean:
            action_code = "SCAN_MESSAGE"
        else:
            action_code = "SCAN_URL"

        score_val = round(float(rscore), 1) if rscore is not None else 0.0
        conf_val = round(float(conf), 1) if conf is not None else 98.4
        level_str = rlevel or ("CRITIQUE" if score_val >= 70 else ("ÉLEVÉ" if score_val >= 50 else "FAIBLE"))
        
        details_str = f"Verdict: {verdict} | Risque: {score_val}/100 ({level_str}) | Confiance IA: {conf_val}% | Réf: {acode}"

        activations.append({
            "id": rid,
            "actor": actor_name,
            "type": "SCAN_RESEARCH",
            "action": action_code,
            "target": target,
            "details": details_str,
            "timestamp": to_utc_iso(rcat)
        })

    # ── 3. Incident dossiers and forensic reporting
    for inc in incidents:
        if isinstance(inc, dict):
            inc_id = inc.get("id")
            inc_title = inc.get("title", "")
            inc_code = inc.get("incident_code", "INC-DEMO")
            inc_status = inc.get("status", "NEW")
            inc_sev = inc.get("severity", "LOW")
            inc_sref = inc.get("source_ref_id")
            inc_cat = inc.get("created_at")
            first_report = None
        else:
            inc_id = inc.id
            inc_title = inc.title
            inc_code = inc.incident_code
            inc_status = inc.status
            inc_sev = inc.severity
            inc_sref = inc.source_ref_id
            inc_cat = inc.created_at
            first_report = inc.reports[0] if getattr(inc, "reports", None) else None

        actor_label = first_report.reporter if (first_report and getattr(first_report, "reporter", None)) else None
        
        if not actor_label and inc_sref:
            if inc_sref in user_id_map:
                actor_label = user_id_map[inc_sref]["name"]
            else:
                linked_anl = db.query(AnalysisRecord).filter(AnalysisRecord.id == inc_sref).first()
                if linked_anl and linked_anl.user_id and str(linked_anl.user_id) in user_id_map:
                    actor_label = user_id_map[str(linked_anl.user_id)]["name"]

        if not actor_label:
            actor_label = "Utilisateur Standard"

        activations.append({
            "id": inc_id,
            "actor": actor_label,
            "type": "INCIDENT_REPORT",
            "action": "TRANSFERT_RAPPORT",
            "target": inc_title,
            "details": f"Dossier {inc_code} | Statut: {inc_status} | Gravité: {inc_sev}",
            "timestamp": to_utc_iso(inc_cat)
        })

    # Deduplicate in case of identical repeated entries
    deduped = []
    seen = set()
    for item in activations:
        dedup_key = f"{item['action']}_{item['actor']}_{item['target']}_{str(item['timestamp'])[:16]}"
        if dedup_key not in seen:
            seen.add(dedup_key)
            deduped.append(item)

    deduped.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return {"activities": deduped, "total": len(deduped)}

