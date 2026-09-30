import os
import sys
from datetime import datetime, timezone

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.database import SessionLocal
from app.db.models import (
    UtilisateurStandard, Enqueteur, Administrateur,
    AnalysisRecord, Incident, IncidentReport, Evidence, AuditLog, SecurityEvent
)
from app.db.mongodb import get_sync_db, init_mongo_indexes

def sync():
    init_mongo_indexes()
    db_sql = SessionLocal()
    db_mongo = get_sync_db()

    print("[1] Syncing users to MongoDB...")
    user_id_map = {}
    
    # Standards
    for u in db_sql.query(UtilisateurStandard).all():
        mongo_u = db_mongo["utilisateurs_standards"].find_one({"email": u.email})
        if not mongo_u:
            doc = {
                "id": str(u.id),
                "nom": u.nom,
                "prenom": u.prenom,
                "email": u.email,
                "hashed_password": u.hashed_password,
                "password_raw": u.password_raw or "User123!",
                "role": u.role,
                "scan_count": u.scan_count or 0,
                "report_count": u.report_count or 0,
                "is_active": u.is_active,
                "preferred_language": u.preferred_language or "fr",
                "last_login": u.last_login or datetime.now(timezone.utc),
                "created_at": u.created_at or datetime.now(timezone.utc)
            }
            db_mongo["utilisateurs_standards"].insert_one(doc)
            user_id_map[str(u.id)] = str(u.id)
        else:
            user_id_map[str(u.id)] = str(mongo_u["id"])
            # Update scan_count and last_login
            db_mongo["utilisateurs_standards"].update_one(
                {"id": mongo_u["id"]},
                {"$set": {
                    "scan_count": max(u.scan_count or 0, mongo_u.get("scan_count", 0)),
                    "report_count": max(u.report_count or 0, mongo_u.get("report_count", 0)),
                    "last_login": u.last_login or mongo_u.get("last_login")
                }}
            )

    # Investigators
    for u in db_sql.query(Enqueteur).all():
        mongo_u = db_mongo["enqueteurs"].find_one({"email": u.email})
        if not mongo_u:
            doc = {
                "id": str(u.id),
                "nom": u.nom,
                "prenom": u.prenom,
                "email": u.email,
                "hashed_password": u.hashed_password,
                "password_raw": u.password_raw or "phishguard2026",
                "role": u.role,
                "badge_number": u.badge_number or "SOC-8849",
                "clearance_level": u.clearance_level or "LEVEL_2_SOC",
                "cases_resolved": u.cases_resolved or 0,
                "scan_count": u.scan_count or 0,
                "report_count": u.report_count or 0,
                "is_active": u.is_active,
                "last_login": u.last_login or datetime.now(timezone.utc),
                "created_at": u.created_at or datetime.now(timezone.utc)
            }
            db_mongo["enqueteurs"].insert_one(doc)
            user_id_map[str(u.id)] = str(u.id)
        else:
            user_id_map[str(u.id)] = str(mongo_u["id"])
            db_mongo["enqueteurs"].update_one(
                {"id": mongo_u["id"]},
                {"$set": {
                    "scan_count": max(u.scan_count or 0, mongo_u.get("scan_count", 0)),
                    "last_login": u.last_login or mongo_u.get("last_login")
                }}
            )

    # Admins
    for u in db_sql.query(Administrateur).all():
        mongo_u = db_mongo["administrateurs"].find_one({"email": u.email})
        if not mongo_u:
            doc = {
                "id": str(u.id),
                "nom": u.nom,
                "prenom": u.prenom,
                "email": u.email,
                "hashed_password": u.hashed_password,
                "password_raw": u.password_raw or "phishguard2026",
                "role": u.role,
                "admin_level": u.admin_level or "SUPER_ADMIN",
                "can_manage_roles": u.can_manage_roles,
                "scan_count": u.scan_count or 0,
                "report_count": u.report_count or 0,
                "is_active": u.is_active,
                "last_login": u.last_login or datetime.now(timezone.utc),
                "created_at": u.created_at or datetime.now(timezone.utc)
            }
            db_mongo["administrateurs"].insert_one(doc)
            user_id_map[str(u.id)] = str(u.id)
        else:
            user_id_map[str(u.id)] = str(mongo_u["id"])
            db_mongo["administrateurs"].update_one(
                {"id": mongo_u["id"]},
                {"$set": {
                    "scan_count": max(u.scan_count or 0, mongo_u.get("scan_count", 0)),
                    "last_login": u.last_login or mongo_u.get("last_login")
                }}
            )

    print(f"User mapping built: {len(user_id_map)} entries.")

    # 2. Sync analyses to MongoDB
    print("[2] Syncing analysis records to MongoDB...")
    sql_analyses = db_sql.query(AnalysisRecord).all()
    synced_anl = 0
    for a in sql_analyses:
        mongo_uid = user_id_map.get(str(a.user_id), str(a.user_id)) if a.user_id else None
        existing = db_mongo["analysis_records"].find_one({"analysis_code": a.analysis_code})
        doc = {
            "id": str(a.id),
            "user_id": mongo_uid,
            "analysis_code": a.analysis_code,
            "analysis_type": a.analysis_type,
            "target_content": a.target_content,
            "verdict": a.verdict,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "ml_confidence": a.ml_confidence,
            "details_json": a.details_json,
            "integrity_hash": a.integrity_hash,
            "is_deleted_by_user": a.is_deleted_by_user,
            "created_at": a.created_at if a.created_at else datetime.now(timezone.utc)
        }
        if existing:
            db_mongo["analysis_records"].update_one(
                {"analysis_code": a.analysis_code},
                {"$set": {"user_id": mongo_uid, "is_deleted_by_user": a.is_deleted_by_user}}
            )
        else:
            db_mongo["analysis_records"].insert_one(doc)
            synced_anl += 1

    total_mongo_anl = db_mongo["analysis_records"].count_documents({})
    print(f"Synced {synced_anl} new analyses. Total in MongoDB now: {total_mongo_anl}")

    # 3. Sync incidents & reports
    print("[3] Syncing incidents & reports to MongoDB...")
    for inc in db_sql.query(Incident).all():
        existing_inc = db_mongo["incidents"].find_one({"incident_code": inc.incident_code})
        inc_doc = {
            "id": str(inc.id),
            "incident_code": inc.incident_code,
            "title": inc.title,
            "category": inc.category,
            "severity": inc.severity,
            "status": inc.status,
            "source_type": inc.source_type,
            "source_ref_id": inc.source_ref_id,
            "summary": inc.summary,
            "evidence_hash": inc.evidence_hash,
            "created_at": inc.created_at or datetime.now(timezone.utc)
        }
        if not existing_inc:
            db_mongo["incidents"].insert_one(inc_doc)
        else:
            db_mongo["incidents"].update_one({"incident_code": inc.incident_code}, {"$set": inc_doc})

    for rpt in db_sql.query(IncidentReport).all():
        existing_rpt = db_mongo["incident_reports"].find_one({"report_code": rpt.report_code})
        rpt_doc = {
            "id": str(rpt.id),
            "report_code": rpt.report_code,
            "incident_id": str(rpt.incident_id),
            "reporter": rpt.reporter,
            "report_payload": rpt.report_payload,
            "integrity_hash": rpt.integrity_hash,
            "verified": rpt.verified,
            "created_at": rpt.created_at or datetime.now(timezone.utc)
        }
        if not existing_rpt:
            db_mongo["incident_reports"].insert_one(rpt_doc)

    for ev in db_sql.query(Evidence).all():
        existing_ev = db_mongo["evidences"].find_one({"id": str(ev.id)})
        if not existing_ev:
            ev_doc = {
                "id": str(ev.id),
                "incident_id": str(ev.incident_id),
                "evidence_type": ev.evidence_type,
                "content": ev.content,
                "sha256_checksum": ev.sha256_checksum,
                "timestamp": ev.timestamp or datetime.now(timezone.utc)
            }
            db_mongo["evidences"].insert_one(ev_doc)

    # 4. Sync audit logs
    print("[4] Syncing audit logs to MongoDB...")
    synced_logs = 0
    for l in db_sql.query(AuditLog).all():
        existing_l = db_mongo["audit_logs"].find_one({"id": str(l.id)})
        if not existing_l:
            l_doc = {
                "id": str(l.id),
                "actor": l.actor,
                "action": l.action,
                "target": l.target,
                "details": l.details,
                "timestamp": l.timestamp or datetime.now(timezone.utc)
            }
            db_mongo["audit_logs"].insert_one(l_doc)
            synced_logs += 1

    total_logs = db_mongo["audit_logs"].count_documents({})
    print(f"Synced {synced_logs} audit logs. Total in MongoDB now: {total_logs}")

    # 5. Sync security events
    print("[5] Syncing security events to MongoDB...")
    for ev in db_sql.query(SecurityEvent).all():
        existing_ev = db_mongo["security_events"].find_one({"id": str(ev.id)})
        if not existing_ev:
            ev_doc = {
                "id": str(ev.id),
                "website_domain": ev.website_domain,
                "source_ip": ev.source_ip,
                "http_method": ev.http_method,
                "request_path": ev.request_path,
                "user_agent": ev.user_agent,
                "status_code": ev.status_code,
                "attack_type": ev.attack_type,
                "severity": ev.severity,
                "confidence": ev.confidence,
                "evidence_payload": ev.evidence_payload,
                "ip_geo_info": ev.ip_geo_info,
                "timestamp": ev.timestamp or datetime.now(timezone.utc)
            }
            db_mongo["security_events"].insert_one(ev_doc)

    print("\n[SUCCESS] MongoDB cyberguard_db has been fully populated and synchronized!")

if __name__ == "__main__":
    sync()
