import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_analyse_url_phishing_detectee_avec_succes():
    """Test 1: Soumission d'une URL de phishing obfusquee -> Verdict MALVEILLANT / RISQUE ELEVE."""
    response = client.post("/api/v1/analyze/url", json={
        "url": "http://192.168.1.100/paypal.com/security-update/login.php?token=827361&verify=1",
        "model_choice": "rf"
    })
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert any(term in data["verdict"] for term in ["MALICIOUS", "SUSPICIOUS", "PHISHING"])
    assert data["risk_score"] > 60.0
    assert "integrity_hash" in data
    assert len(data["integrity_hash"]) == 64  # Empreinte SHA-256

def test_analyse_url_legitime_score_faible():
    """Test 2: Soumission d'une URL institutionnelle legitime -> Score faible et verdict sain."""
    response = client.post("/api/v1/analyze/url", json={
        "url": "https://www.google.com/search?q=cybersecurity",
        "model_choice": "rf"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] < 50.0
    assert any(term in data["verdict"] for term in ["LEGITIMATE", "CLEAN", "SAFE"])

def test_analyse_message_sms_smishing_nlp():
    """Test 3: Soumission d'un SMS d'ingenierie sociale -> Marqueurs d'urgence et URL extraits."""
    response = client.post("/api/v1/analyze/text", json={
        "text": "URGENT ALERTE : Votre compte bancaire est suspendu suite a une activite suspecte. Cliquez ici immediatement pour verifier : http://banque-securite-connexion.xyz",
        "sender": "+33600000000"
    })
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert data["risk_score"] > 50.0
    assert "extracted_urls" in data or "indicators" in data

def test_calcul_empreinte_integrite_sha256():
    """Test 4: Verification du scellement d'integrite SHA-256 sur chaque resultat."""
    from app.core.security import generate_sha256_hash
    test_content = "CyberGuard-Audit-Proof-2026"
    digest = generate_sha256_hash(test_content)
    assert len(digest) == 64
    assert digest == generate_sha256_hash(test_content)
