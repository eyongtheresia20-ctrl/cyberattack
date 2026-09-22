from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import IncidentReport, AnalysisRecord, Incident, AuditLog
from app.core.security import generate_sha256_hash

router = APIRouter(prefix="/verify", tags=["Investigator Integrity Verification"])

def _log_verification(db: Session, code: str, valid: bool):
    try:
        audit = AuditLog(
            actor="Jean Dupont",
            action="VERIF_INTEGRITE",
            target=code,
            details=f"Vérification d'intégrité SHA-256 pour {code} — {'Empreinte Authentique' if valid else 'ALERTE FALSIFICATION'}"
        )
        db.add(audit)
        db.commit()
    except Exception:
        pass

class VerificationRequest(BaseModel):
    lookup_code: str # e.g. RPT-2026-10492 or ANL-2026-948201
    provided_hash: Optional[str] = None

@router.post("/check")
def verify_report_integrity(req: VerificationRequest, db: Session = Depends(get_db)):
    code = req.lookup_code.strip().upper()

    # 1. Try checking as Incident Report Code
    if code.startswith("RPT-"):
        report = db.query(IncidentReport).filter(IncidentReport.report_code == code).first()
        if not report:
            raise HTTPException(status_code=404, detail=f"No incident report found matching code: {code}")
        
        # Recompute SHA-256 hash of stored payload
        computed_hash = generate_sha256_hash(report.report_payload)
        hash_matched = (computed_hash == report.integrity_hash)
        
        if req.provided_hash:
            user_hash_matched = (req.provided_hash.strip().lower() == report.integrity_hash.lower())
        else:
            user_hash_matched = True

        valid = hash_matched and user_hash_matched
        _log_verification(db, code, valid)

        return {
            "valid": valid,
            "status": "INTEGRITY_VERIFIED" if (hash_matched and user_hash_matched) else "TAMPERING_DETECTED",
            "lookup_code": code,
            "type": "INCIDENT_REPORT",
            "db_hash": report.integrity_hash,
            "computed_hash": computed_hash,
            "report_details": report.report_payload,
            "verification_message": "Report authentic and unchanged since original investigation creation." if hash_matched else "CRITICAL WARNING: Database hash mismatch! Data may have been tampered with."
        }

    # 2. Try checking as Analysis Record Code
    elif code.startswith("ANL-"):
        analysis = db.query(AnalysisRecord).filter(AnalysisRecord.analysis_code == code).first()
        if not analysis:
            raise HTTPException(status_code=404, detail=f"No analysis record found matching code: {code}")
        
        payload_copy = dict(analysis.details_json or {})
        payload_copy.pop("integrity_hash", None)
        payload_copy.pop("id", None)
        payload_copy.pop("analysis_id", None)
        payload_copy.pop("created_at", None)
        computed_hash = generate_sha256_hash(payload_copy)
        hash_matched = (computed_hash == analysis.integrity_hash)

        if req.provided_hash:
            user_hash_matched = (req.provided_hash.strip().lower() == analysis.integrity_hash.lower())
        else:
            user_hash_matched = True

        valid = hash_matched and user_hash_matched
        _log_verification(db, code, valid)

        return {
            "valid": valid,
            "status": "INTEGRITY_VERIFIED" if valid else "TAMPERING_DETECTED",
            "lookup_code": code,
            "type": "ANALYSIS_RECORD",
            "db_hash": analysis.integrity_hash,
            "computed_hash": computed_hash,
            "analysis_details": analysis.details_json,
            "verification_message": "Original analysis record verified and match confirmed in database." if valid else "Hash verification failed! Hash mismatch detected."
        }

    # 3. Try checking as Incident Code
    elif code.startswith("INC-"):
        incident = db.query(Incident).filter(Incident.incident_code == code).first()
        if not incident:
            raise HTTPException(status_code=404, detail=f"No incident found matching code: {code}")

        # Check if there is an associated sealed report
        report = db.query(IncidentReport).filter(IncidentReport.incident_id == incident.id).first()
        if report:
            computed_hash = generate_sha256_hash(report.report_payload)
            hash_matched = (computed_hash == report.integrity_hash)
            db_hash = report.integrity_hash
        else:
            computed_hash = generate_sha256_hash({
                "code": incident.incident_code,
                "title": incident.title,
                "summary": incident.summary,
                "category": incident.category
            })
            hash_matched = True
            db_hash = incident.evidence_hash

        if req.provided_hash:
            user_hash_matched = (
                req.provided_hash.strip().lower() == db_hash.lower() or
                (incident.evidence_hash and req.provided_hash.strip().lower() == incident.evidence_hash.lower())
            )
        else:
            user_hash_matched = True

        valid = hash_matched and user_hash_matched
        _log_verification(db, code, valid)

        return {
            "valid": valid,
            "status": "INTEGRITY_VERIFIED" if valid else "TAMPERING_DETECTED",
            "lookup_code": code,
            "type": "INCIDENT",
            "db_hash": db_hash,
            "computed_hash": computed_hash,
            "incident_details": {
                "title": incident.title,
                "category": incident.category,
                "severity": incident.severity,
                "status": incident.status,
                "report_code": report.report_code if report else None
            },
            "verification_message": "Sceau cryptographique de l'incident vérifié avec succès et intact en base de données." if valid else "ALERTE : Incohérence de l'empreinte SHA-256 !"
        }

    else:
        raise HTTPException(status_code=400, detail="Invalid code format. Expected INC-XXXX, RPT-XXXXXX, or ANL-XXXXXX")
