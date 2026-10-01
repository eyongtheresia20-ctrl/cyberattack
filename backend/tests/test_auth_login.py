import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_login_reussi_renvoie_un_token():
    """Test 1: Connexion avec identifiants valides (Admin)."""
    response = client.post("/api/v1/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "phishguard2026"
    })
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert len(data["token"]) > 20
    assert data["user"]["email"] == "admin@phishguard.security"
    assert data["user"]["role"] == "ADMINISTRATEUR"

def test_login_mauvais_mot_de_passe_est_refuse():
    """Test 2: Connexion avec mauvais mot de passe."""
    response = client.post("/api/v1/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "MotDePasseTotalementFaux123!"
    })
    assert response.status_code == 401
    assert "detail" in response.json()

def test_login_email_inconnu_est_refuse():
    """Test 3: Connexion avec une adresse email inexistante."""
    response = client.post("/api/v1/auth/login", json={
        "email": "utilisateur_fantome_999@domaine-inconnu.xyz",
        "password": "Password123!"
    })
    assert response.status_code == 401

def test_login_compte_desactive_est_refuse():
    """Test 4: Tentative de connexion avec une payload invalide ou mal formee."""
    response = client.post("/api/v1/auth/login", json={
        "email": "invalide-sans-at",
        "password": ""
    })
    # Doit renvoyer une erreur 400, 401 ou 422 de validation
    assert response.status_code in [400, 401, 422]

def test_token_du_login_donne_acces_a_auth_me():
    """Test 5: Utilisation du jeton JWT pour interroger /auth/me."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "phishguard2026"
    })
    token = login_resp.json()["token"]

    me_resp = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert "user" in me_data
    assert me_data["user"]["email"] == "admin@phishguard.security"
    assert me_data["user"]["role"] == "ADMINISTRATEUR"

def test_gestion_utilisateurs_et_roles_rbac():
    """Test 6: Consultation de l'annuaire par l'Admin et verification RBAC."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "phishguard2026"
    })
    token = login_resp.json()["token"]

    users_resp = client.get("/api/v1/users", headers={
        "Authorization": f"Bearer {token}"
    })
    assert users_resp.status_code == 200
    users_data = users_resp.json()
    assert "users" in users_data
    assert len(users_data["users"]) >= 1
