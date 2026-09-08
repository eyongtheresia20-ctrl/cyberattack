import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Float, Integer, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

# ==========================================
# 1. UTILISATEUR STANDARD TABLE
# ==========================================
class UtilisateurStandard(Base):
    __tablename__ = "utilisateurs_standards"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), default="UTILISATEUR_STANDARD", nullable=False)
    preferred_language = Column(String(10), default="fr")
    scan_count = Column(Integer, default=0)
    report_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    password_raw = Column(String(255), nullable=True)
    last_login = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# ==========================================
# 2. ENQUETEUR TABLE
# ==========================================
class Enqueteur(Base):
    __tablename__ = "enqueteurs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), default="ENQUETEUR", nullable=False)
    badge_number = Column(String(50), nullable=True)
    clearance_level = Column(String(50), default="LEVEL_2_SOC")
    cases_resolved = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    password_raw = Column(String(255), nullable=True)
    last_login = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# ==========================================
# 3. ADMINISTRATEUR TABLE
# ==========================================
class Administrateur(Base):
    __tablename__ = "administrateurs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), default="ADMINISTRATEUR", nullable=False)
    admin_level = Column(String(50), default="SUPER_ADMIN")
    can_manage_roles = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    password_raw = Column(String(255), nullable=True)
    last_login = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ==========================================
# 4. ANALYSIS RECORDS TABLE
# ==========================================
class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("utilisateurs_standards.id"), nullable=True, index=True)
    analysis_code = Column(String(20), unique=True, nullable=False, index=True) # e.g. ANL-2026-0001
    analysis_type = Column(String(20), nullable=False) # URL, EMAIL, MESSAGE
    target_content = Column(Text, nullable=False)
    verdict = Column(String(20), nullable=False) # PHISHING, LEGITIMATE, SUSPICIOUS, MALICIOUS
    risk_score = Column(Float, nullable=False) # 0 to 100
    risk_level = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    ml_confidence = Column(Float, nullable=False) # 0.0 to 1.0
    details_json = Column(JSON, nullable=True) # Full ML features, rule triggers, Threat Intel
    integrity_hash = Column(String(64), nullable=False) # SHA-256 evidence hash
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ==========================================
# 5. SECURITY EVENTS TABLE
# ==========================================
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    website_domain = Column(String(100), nullable=False, default="phishguard-demo.sec")
    source_ip = Column(String(45), nullable=False)
    http_method = Column(String(10), nullable=False) # GET, POST, PUT, DELETE
    request_path = Column(Text, nullable=False)
    user_agent = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=False, default=200)
    attack_type = Column(String(50), nullable=False) # SQLi, XSS, BruteForce, PathTraversal, Normal
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=0.95)
    evidence_payload = Column(Text, nullable=True)
    ip_geo_info = Column(JSON, nullable=True) # Geolocation, ASN, VPN detection
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ==========================================
# 6. INCIDENTS TABLE
# ==========================================
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_code = Column(String(20), unique=True, nullable=False, index=True) # e.g. INC-2026-0001
    title = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False) # Phishing, SQLi, Brute Force, Malicious URL
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), default="NEW", nullable=False) # NEW, INVESTIGATING, RESOLVED, CLOSED
    source_type = Column(String(50), nullable=False) # USER_REPORT, WAF_TELEMETRY, THREAT_INTEL
    source_ref_id = Column(String(36), nullable=True)
    summary = Column(Text, nullable=False)
    evidence_hash = Column(String(64), nullable=False) # SHA-256 proof hash
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    evidences = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("IncidentReport", back_populates="incident", cascade="all, delete-orphan")


# ==========================================
# 7. EVIDENCE ITEMS TABLE
# ==========================================
class Evidence(Base):
    __tablename__ = "evidences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String(50), nullable=False) # URL_RAW, EMAIL_HEADER, HTTP_PAYLOAD, PCAP
    content = Column(Text, nullable=False)
    sha256_checksum = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="evidences")


# ==========================================
# 8. INCIDENT REPORTS TABLE
# ==========================================
class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_code = Column(String(30), unique=True, nullable=False, index=True) # e.g. RPT-2026-0001
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    reporter = Column(String(100), default="Security Analyst")
    report_payload = Column(JSON, nullable=False)
    integrity_hash = Column(String(64), nullable=False) # Cryptographic signature
    verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="reports")


# ==========================================
# 9. AUDIT LOGS TABLE
# ==========================================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
