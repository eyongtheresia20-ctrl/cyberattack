from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import IncidentReport, AnalysisRecord
from app.core.security import generate_sha256_hash

router = APIRouter(prefix="/verify", tags=["Investigator Integrity Verification"])

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

        return {
            "valid": hash_matched and user_hash_matched,
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
        
        computed_hash = generate_sha256_hash(analysis.details_json)
        hash_matched = (computed_hash == analysis.integrity_hash)

        return {
            "valid": hash_matched,
            "status": "INTEGRITY_VERIFIED" if hash_matched else "TAMPERING_DETECTED",
            "lookup_code": code,
            "type": "ANALYSIS_RECORD",
            "db_hash": analysis.integrity_hash,
            "computed_hash": computed_hash,
            "analysis_details": analysis.details_json,
            "verification_message": "Original analysis record verified and match confirmed in database." if hash_matched else "Hash verification failed!"
        }

    else:
        raise HTTPException(status_code=400, detail="Invalid code format. Expected RPT-XXXXXX or ANL-XXXXXX")
