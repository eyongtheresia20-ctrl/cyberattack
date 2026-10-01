import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_creation_et_transfert_dossier_incident():
    """Test 1: Creation d'un incident de securite signale."""
    create_resp = client.post("/api/v1/incidents/create", json={
        "title": "Attaque Phishing Bancaire par Typosquattage",
        "category": "Phishing",
        "severity": "HIGH",
        "summary": "Domaine usurpant une banque nationale avec formulaire de capture d'identifiants.",
        "source_type": "USER_REPORT"
    })
    assert create_resp.status_code == 200
    inc_data = create_resp.json()
    assert "id" in inc_data
    assert "incident_code" in inc_data
    assert inc_data["status"] == "NEW"
    assert len(inc_data["evidence_hash"]) == 64

def test_assignation_et_cycle_de_vie_enqueteur_soc():
    """Test 2: Prise en charge par l'enqueteur SOC et evolution du statut."""
    # 1. Creer un incident
    create_resp = client.post("/api/v1/incidents/create", json={
        "title": "Scan URL Suspecte Enquete",
        "category": "Malware",
        "severity": "CRITICAL",
        "summary": "Distribution de binaire malveillant.",
        "source_type": "URL_ANALYSIS"
    })
    inc_id = create_resp.json()["id"]

    # 2. Passage en INVESTIGATING
    patch_resp = client.patch(f"/api/v1/incidents/{inc_id}/status", json={
        "status": "INVESTIGATING",
        "notes": "Analyse forensique en cours dans la sandbox."
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"

    # 3. Resolution du dossier
    resolve_resp = client.patch(f"/api/v1/incidents/{inc_id}/status", json={
        "status": "RESOLVED",
        "notes": "Nom de domaine bloque au niveau du pare-feu applicatif."
    })
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "RESOLVED"

def test_generation_rapport_forensique_scelle():
    """Test 3: Cloture et generation du rapport forensique scelle SHA-256."""
    create_resp = client.post("/api/v1/incidents/create", json={
        "title": "Dossier Cloture avec Rapport",
        "category": "Phishing",
        "severity": "HIGH",
        "summary": "Campagne SMS ciblee contre les salaries.",
        "source_type": "USER_REPORT"
    })
    inc_id = create_resp.json()["id"]

    rpt_resp = client.post(f"/api/v1/incidents/{inc_id}/generate-report?reporter_name=Analyste_SOC_Alex")
    assert rpt_resp.status_code == 200
    rpt_data = rpt_resp.json()
    assert "report" in rpt_data
    assert "integrity_hash" in rpt_data
    assert len(rpt_data["integrity_hash"]) == 64
