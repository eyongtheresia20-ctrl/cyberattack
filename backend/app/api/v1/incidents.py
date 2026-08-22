import random
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.database import get_db
from app.db.models import Incident, Evidence, IncidentReport, AnalysisRecord, SecurityEvent
from app.core.security import generate_sha256_hash

router = APIRouter(prefix="/incidents", tags=["Incident Management & Evidence Ledger"])

class IncidentCreateRequest(BaseModel):
    title: str
    category: str
    severity: str
    summary: str
    source_type: str = "MANUAL_REPORT"
    source_ref_id: Optional[str] = None

@router.get("")
def list_incidents(db: Session = Depends(get_db)):
    """Fetch all security incidents with attached evidence count."""
    incidents = db.query(Incident).order_by(desc(Incident.created_at)).all()
    return incidents

@router.get("/{incident_id}")
def get_incident_details(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    evidences = db.query(Evidence).filter(Evidence.incident_id == incident.id).all()
    reports = db.query(IncidentReport).filter(IncidentReport.incident_id == incident.id).all()

    return {
        "incident": incident,
        "evidences": evidences,
        "reports": reports
    }

@router.post("/create")
def create_incident(req: IncidentCreateRequest, db: Session = Depends(get_db)):
    inc_code = f"INC-2026-{random.randint(1000, 9999)}"
    
    evidence_hash = generate_sha256_hash({
        "code": inc_code,
        "title": req.title,
        "summary": req.summary,
        "category": req.category
    })

    incident = Incident(
        incident_code=inc_code,
        title=req.title,
        category=req.category,
        severity=req.severity,
        status="NEW",
        source_type=req.source_type,
        source_ref_id=req.source_ref_id,
        summary=req.summary,
        evidence_hash=evidence_hash
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident

@router.post("/{incident_id}/generate-report")
def generate_incident_report(incident_id: str, reporter_name: str = "Security Investigator", db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    report_code = f"RPT-2026-{random.randint(10000, 99999)}"

    # Retrieve attached analysis if present
    analysis_data = None
    if incident.source_type == "URL_ANALYSIS" and incident.source_ref_id:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == incident.source_ref_id).first()
        if record:
            analysis_data = record.details_json
    elif incident.source_type == "LOG_EVENT" and incident.source_ref_id:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == incident.source_ref_id).first()
        if event:
            analysis_data = {
                "source_ip": event.source_ip,
                "attack_type": event.attack_type,
                "request_path": event.request_path,
                "user_agent": event.user_agent,
                "ip_geo_info": event.ip_geo_info
            }

    report_payload = {
        "report_code": report_code,
        "incident_code": incident.incident_code,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "reporter": reporter_name,
        "summary": incident.summary,
        "analysis_details": analysis_data,
        "evidence_hash": incident.evidence_hash
    }

    integrity_hash = generate_sha256_hash(report_payload)

    report = IncidentReport(
        report_code=report_code,
        incident_id=incident.id,
        reporter=reporter_name,
        report_payload=report_payload,
        integrity_hash=integrity_hash,
        verified=True
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "report": report,
        "integrity_hash": integrity_hash
    }

class StatusUpdateRequest(BaseModel):
    status: str # NEW, INVESTIGATING, RESOLVED, CLOSED
    notes: Optional[str] = None

@router.patch("/{incident_id}/status")
def update_incident_status(incident_id: str, req: StatusUpdateRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    if req.status not in ["NEW", "INVESTIGATING", "RESOLVED", "CLOSED"]:
        raise HTTPException(status_code=400, detail="Statut d'incident invalide")
    
    incident.status = req.status
    if req.notes:
        incident.summary = f"{incident.summary}\n\n[Note Enquêteur - {req.status}]: {req.notes}"
    
    db.commit()
    db.refresh(incident)
    return incident

class UserScanReportRequest(BaseModel):
    title: str
    target: str # URL or Email/SMS content
    scan_type: str # URL, EMAIL, MESSAGE
    verdict: str
    risk_score: float
    details: Optional[dict] = None
    reporter_name: Optional[str] = "Utilisateur Standard"
    reporter_email: Optional[str] = None

@router.post("/submit-user-report")
def submit_user_report(req: UserScanReportRequest, db: Session = Depends(get_db)):
    inc_code = f"INC-2026-{random.randint(1000, 9999)}"
    
    summary_text = f"Signalement par {req.reporter_name} ({req.reporter_email or 'Anonyme'}). Target: {req.target}. Verdict: {req.verdict} (Risk: {req.risk_score}/100)."
    
    evidence_hash = generate_sha256_hash({
        "code": inc_code,
        "target": req.target,
        "verdict": req.verdict,
        "risk_score": req.risk_score,
        "reporter": req.reporter_email
    })
    
    incident = Incident(
        incident_code=inc_code,
        title=f"[User Report] {req.title}",
        category="Phishing Campaign" if req.scan_type in ["URL", "EMAIL"] else "Social Engineering",
        severity="HIGH" if req.risk_score >= 65 else ("MEDIUM" if req.risk_score >= 35 else "LOW"),
        status="NEW",
        source_type=f"{req.scan_type}_USER_REPORT",
        summary=summary_text,
        evidence_hash=evidence_hash
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    # Auto-generate Evidence item
    ev = Evidence(
        incident_id=incident.id,
        evidence_type="USER_SUBMISSION_PAYLOAD",
        content=f"Payload: {req.target}\nDetails: {req.details}",
        sha256_checksum=evidence_hash
    )
    db.add(ev)
    
    # Auto-generate sealed IncidentReport
    report_code = f"RPT-2026-{random.randint(10000, 99999)}"
    report_payload = {
        "report_code": report_code,
        "incident_code": inc_code,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "reporter_name": req.reporter_name,
        "reporter_email": req.reporter_email,
        "target_content": req.target,
        "verdict": req.verdict,
        "risk_score": req.risk_score,
        "analysis_details": req.details,
        "evidence_hash": evidence_hash
    }
    integrity_hash = generate_sha256_hash(report_payload)
    
    report = IncidentReport(
        report_code=report_code,
        incident_id=incident.id,
        reporter=req.reporter_name or "Utilisateur Standard",
        report_payload=report_payload,
        integrity_hash=integrity_hash,
        verified=True
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    return {
        "incident": incident,
        "report": report,
        "integrity_hash": integrity_hash,
        "message": "Signalement transmis avec succès à la file des enquêtes"
    }

