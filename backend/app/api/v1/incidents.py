import random
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

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

@router.get("/stats")
def get_incident_stats(db: Session = Depends(get_db)):
    """Return live database statistics directly for investigator dashboard."""
    total_incidents = db.query(Incident).count()
    new_incidents = db.query(Incident).filter(Incident.status == "NEW").count()
    investigating_incidents = db.query(Incident).filter(Incident.status == "INVESTIGATING").count()
    resolved_incidents = db.query(Incident).filter(Incident.status.in_(["RESOLVED", "CLOSED"])).count()
    
    categories = db.query(Incident.category, func.count(Incident.id)).group_by(Incident.category).all()
    categories_breakdown = [{"name": cat or "Autre", "count": cnt} for cat, cnt in categories]
    
    user_reports = db.query(Incident).filter(Incident.source_type.like("%USER_REPORT%")).count()
    waf_events = db.query(Incident).filter(Incident.source_type.like("%LOG_EVENT%")).count()
    other_sources = max(0, total_incidents - (user_reports + waf_events))

    return {
        "total_incidents": total_incidents,
        "new_incidents": new_incidents,
        "investigating_incidents": investigating_incidents,
        "resolved_incidents": resolved_incidents,
        "categories_breakdown": categories_breakdown,
        "sources": {
            "user_reports": user_reports,
            "waf_events": waf_events,
            "other_sources": other_sources
        }
    }

@router.get("")
def list_incidents(db: Session = Depends(get_db)):
    """Fetch all security incidents and reports enriched with user submission details."""
    incidents = db.query(Incident).order_by(desc(Incident.created_at)).all()
    results = []
    for inc in incidents:
        report = db.query(IncidentReport).filter(IncidentReport.incident_id == inc.id).first()
        evidence = db.query(Evidence).filter(Evidence.incident_id == inc.id).first()
        
        rep_payload = report.report_payload if report and report.report_payload else {}
        
        # Determine target content
        target = rep_payload.get("target_content")
        if not target and evidence and "Payload: " in (evidence.content or ""):
            try:
                target = evidence.content.split("Payload: ")[1].split("\n")[0]
            except Exception:
                target = None
        if not target and "Target: " in (inc.summary or ""):
            try:
                target = inc.summary.split("Target: ")[1].split(". Verdict:")[0]
            except Exception:
                target = None

        # Determine reporter
        reporter_name = rep_payload.get("reporter_name") or (report.reporter if report else None)
        reporter_email = rep_payload.get("reporter_email")
        if not reporter_name and "Signalement par " in (inc.summary or ""):
            try:
                part = inc.summary.split("Signalement par ")[1].split(". Target:")[0]
                if "(" in part:
                    reporter_name = part.split("(")[0].strip()
                    reporter_email = part.split("(")[1].replace(")", "").strip()
                else:
                    reporter_name = part.strip()
            except Exception:
                pass

        verdict = rep_payload.get("verdict")
        risk_score = rep_payload.get("risk_score")
        if verdict is None and "Verdict: " in (inc.summary or ""):
            try:
                verdict = inc.summary.split("Verdict: ")[1].split(" (Risk:")[0].strip()
            except Exception:
                pass
        if risk_score is None and "Risk: " in (inc.summary or ""):
            try:
                risk_score = float(inc.summary.split("Risk: ")[1].split("/100")[0].strip())
            except Exception:
                pass

        # Extract user notes and investigator notes
        user_notes = ""
        investigator_notes = ""
        if rep_payload.get("analysis_details") and isinstance(rep_payload["analysis_details"], dict):
            user_notes = rep_payload["analysis_details"].get("user_observations", "")
        if "[Note Enquêteur" in (inc.summary or ""):
            try:
                parts = inc.summary.split("[Note Enquêteur")
                investigator_notes = "[Note Enquêteur" + parts[-1]
            except Exception:
                pass

        results.append({
            "id": inc.id,
            "incident_code": inc.incident_code,
            "report_code": report.report_code if report else None,
            "title": inc.title,
            "category": inc.category,
            "severity": inc.severity,
            "status": inc.status,
            "source_type": inc.source_type,
            "summary": inc.summary,
            "evidence_hash": inc.evidence_hash,
            "integrity_hash": report.integrity_hash if report else inc.evidence_hash,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "reporter_name": reporter_name or "Alice Martin",
            "reporter_email": reporter_email or "alice.martin@example.com",
            "target": target or inc.title,
            "verdict": verdict or ("PHISHING" if inc.severity in ["HIGH", "CRITICAL"] else "SUSPECT"),
            "risk_score": risk_score if risk_score is not None else (85.0 if inc.severity in ["HIGH", "CRITICAL"] else 30.0),
            "analysis_details": rep_payload.get("analysis_details") or {},
            "report_payload": rep_payload,
            "user_notes": user_notes,
            "investigator_notes": investigator_notes
        })
    return results

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

class IncidentUpdateRequest(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    verdict: Optional[str] = None
    investigator_notes: Optional[str] = None

@router.put("/{incident_id}")
@router.patch("/{incident_id}")
def update_incident_full(incident_id: str, req: IncidentUpdateRequest, db: Session = Depends(get_db)):
    """Full update/enrichment of an incident report by an investigator."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")

    if req.title:
        incident.title = req.title
    if req.category:
        incident.category = req.category
    if req.severity:
        incident.severity = req.severity
    if req.status:
        if req.status not in ["NEW", "INVESTIGATING", "RESOLVED", "CLOSED"]:
            raise HTTPException(status_code=400, detail="Statut d'incident invalide")
        incident.status = req.status
    if req.investigator_notes:
        # Keep clean notes in summary
        if "[Note Enquêteur" in incident.summary:
            base_summary = incident.summary.split("[Note Enquêteur")[0].strip()
            incident.summary = f"{base_summary}\n\n[Note Enquêteur - {incident.status}]: {req.investigator_notes}"
        else:
            incident.summary = f"{incident.summary}\n\n[Note Enquêteur - {incident.status}]: {req.investigator_notes}"

    # Also update associated sealed report payload if verdict was updated
    report = db.query(IncidentReport).filter(IncidentReport.incident_id == incident.id).first()
    if report and report.report_payload:
        new_payload = dict(report.report_payload)
        if req.title:
            new_payload["title"] = req.title
        if req.severity:
            new_payload["severity"] = req.severity
        if req.verdict:
            new_payload["verdict"] = req.verdict
        if req.investigator_notes:
            new_payload["investigator_notes"] = req.investigator_notes
        
        report.report_payload = new_payload
        report.integrity_hash = generate_sha256_hash(new_payload)

    db.commit()
    db.refresh(incident)
    return {
        "success": True,
        "message": "Rapport et incident mis à jour avec succès",
        "incident": incident
    }

@router.delete("/{incident_id}")
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    """Delete an incident and all associated evidence and reports."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")

    # Cleanly remove evidences & reports
    db.query(Evidence).filter(Evidence.incident_id == incident.id).delete()
    db.query(IncidentReport).filter(IncidentReport.incident_id == incident.id).delete()
    db.delete(incident)
    db.commit()

    return {
        "success": True,
        "message": f"Incident {incident.incident_code} et rapports associés supprimés avec succès",
        "id": incident_id
    }


