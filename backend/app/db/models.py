import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Float, Integer, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="User")  # User, Investigator, Admin
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_code = Column(String(20), unique=True, nullable=False, index=True) # e.g. ANL-2026-0001
    analysis_type = Column(String(20), nullable=False) # URL, EMAIL, MESSAGE
    target_content = Column(Text, nullable=False) # The URL or text content
    verdict = Column(String(20), nullable=False) # PHISHING, LEGITIMATE, SUSPICIOUS, MALICIOUS
    risk_score = Column(Float, nullable=False) # 0.0 to 100.0
    risk_level = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    ml_confidence = Column(Float, nullable=False)
    details_json = Column(JSON, nullable=True) # Feature vector, rules triggered, API results
    integrity_hash = Column(String(64), nullable=False) # SHA-256 hash of analysis
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    website_domain = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    http_method = Column(String(10), nullable=False)
    request_path = Column(Text, nullable=False)
    user_agent = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=False)
    attack_type = Column(String(50), nullable=False) # SQLi, XSS, Brute Force, Path Traversal, Recon Scanning
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False)
    evidence_payload = Column(Text, nullable=True)
    ip_geo_info = Column(JSON, nullable=True) # Country, ASN, Org
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_code = Column(String(20), unique=True, nullable=False, index=True) # e.g. INC-2026-001
    title = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False) # Phishing Campaign, Web Attack, Recon, Credential Harvesting
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), default="NEW") # NEW, INVESTIGATING, RESOLVED, CLOSED
    source_type = Column(String(50), nullable=False) # URL_ANALYSIS, LOG_EVENT, MESSAGE_ANALYSIS
    source_ref_id = Column(String(36), nullable=True) # Reference to AnalysisRecord or SecurityEvent
    summary = Column(Text, nullable=False)
    evidence_hash = Column(String(64), nullable=False) # Cryptographic evidence digest
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    evidences = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("IncidentReport", back_populates="incident", cascade="all, delete-orphan")

class Evidence(Base):
    __tablename__ = "evidences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    evidence_type = Column(String(50), nullable=False) # LOG_ENTRY, URL_VECTOR, HEADERS, PAYLOAD
    content = Column(Text, nullable=False)
    sha256_checksum = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="evidences")

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_code = Column(String(30), unique=True, nullable=False, index=True) # RPT-2026-0001
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    reporter = Column(String(100), default="Security Analyst")
    report_payload = Column(JSON, nullable=False) # Complete snapshot of investigation
    integrity_hash = Column(String(64), nullable=False) # SHA-256 signature
    verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="reports")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
