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
