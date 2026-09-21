from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, AuditLog, AnalysisRecord, Incident
from app.api.v1.auth import get_current_user, find_user_by_id

router = APIRouter(prefix="/users", tags=["User Management"])

class RoleUpdateRequest(BaseModel):
    new_role: str # UTILISATEUR_STANDARD or ENQUETEUR

@router.get("", response_model=dict)
def list_users(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")
    
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
        details=f"Changement de rôle et transfert de table : {old_role} -> {req.new_role}"
    )
    db.add(audit)
    db.commit()
    
    return {
        "message": f"Rôle mis à jour avec succès en {target_user.role} dans la table {target_user.__tablename__}",
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

    return {"success": True, "message": f"Compte {target_email} supprimé avec succès."}

@router.get("/activity-logs", response_model=dict)
def get_user_activity_logs(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")

    # ── Build sets for all Administrateur accounts — their activity is fully hidden
    admin_emails = {a.email for a in db.query(Administrateur).all()}
    admin_names  = {f"{a.prenom} {a.nom}" for a in db.query(Administrateur).all()}

    # ── Build a quick lookup: user_id -> (prenom, nom, role) for standard users & investigators
    std_users  = db.query(UtilisateurStandard).all()
    enq_users  = db.query(Enqueteur).all()
    all_non_admin_users = std_users + enq_users

    user_id_map = {}
    for u in all_non_admin_users:
        user_id_map[u.id] = {
            "name": f"{u.prenom} {u.nom}",
            "role": u.role
        }

    logs     = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(150).all()
    records  = db.query(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).limit(50).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all()

    activations = []
    seen_log_keys = set()

    # ── 1. AuditLog entries — exclude any entry linked to an admin actor or target
    for l in logs:
        actor_str = l.actor or ""
        # Skip entries originating from admin accounts
        if actor_str in admin_names:
            continue
        # Skip entries whose target is an admin email
        if l.target and l.target in admin_emails:
            continue

        key = f"{l.action}_{l.target}_{l.timestamp}"
        seen_log_keys.add(key)
        log_type = "SERVICE_ERROR" if l.action == "SERVICE_PIPELINE_ERROR" else "AUDIT"
        activations.append({
            "id": l.id,
            "actor": actor_str or "Utilisateur",
            "type": log_type,
            "action": l.action or "ACTION",
            "target": l.target or "-",
            "details": l.details or "Action système enregistrée",
            "timestamp": l.timestamp.isoformat() if l.timestamp else None
        })

    # ── 2. Login sessions — only standard users and investigators
    for u in all_non_admin_users:
        if getattr(u, "last_login", None):
            key = f"LOGIN_{u.email}_{u.last_login}"
            if key not in seen_log_keys:
                role_label = "Enquêteur SOC" if u.role == "ENQUETEUR" else "Utilisateur Standard"
                activations.append({
                    "id": f"login-{u.id}",
                    "actor": f"{u.prenom} {u.nom}",
                    "type": "AUDIT",
                    "action": "LOGIN",
                    "target": u.email,
                    "details": f"Session active ({role_label}) — Connexion enregistrée",
                    "timestamp": u.last_login.isoformat()
                })

    # ── 3. Analysis scan records — look up actual user name from user_id mapping
    for r in records:
        uid = getattr(r, "user_id", None)
        user_info = user_id_map.get(uid) if uid else None
        actor_name = user_info["name"] if user_info else "Utilisateur Standard"
        activations.append({
            "id": r.id,
            "actor": actor_name,
            "type": "SCAN_RESEARCH",
            "action": f"SCAN_{r.analysis_type}",
            "target": r.target_content,
            "details": f"Verdict: {r.verdict} (Risk: {r.risk_score}/100) — Réf: {r.analysis_code}",
            "timestamp": r.created_at.isoformat() if r.created_at else None
        })

    # ── 4. Incident dossiers — show readable source label
    for inc in incidents:
        # Map source_type to a human-readable actor label
        source_map = {
            "USER_REPORT": "Utilisateur Standard",
            "WAF_TELEMETRY": "Système WAF",
            "THREAT_INTEL": "Renseignement Menaces"
        }
        actor_label = source_map.get(inc.source_type, inc.source_type or "Enquêteur SOC")
        activations.append({
            "id": inc.id,
            "actor": actor_label,
            "type": "INCIDENT_REPORT",
            "action": "INCIDENT_DOSSIER",
            "target": inc.title,
            "details": f"Dossier {inc.incident_code} (Statut: {inc.status}, Sévérité: {inc.severity})",
            "timestamp": inc.created_at.isoformat() if inc.created_at else None
        })

    activations.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return {"activities": activations, "total": len(activations)}

