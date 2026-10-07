"""
========================================================================================
CYBERGUARD / PHISHGUARD — SUITE DE TESTS D'AUTHENTIFICATION ET CONTRÔLE DES ACCÈS (RBAC)
========================================================================================
Description :
Ce script de test valide l'ensemble du cycle de vie de gestion des utilisateurs :
1. Enregistrement des comptes (Administrateur & Utilisateur Standard).
2. Authentification sécurisée (Génération et validation du token JWT Bearer).
3. Consultation de l'annuaire des utilisateurs et promotion de rôle (Standard -> Enquêteur).
4. Vérification de la règle de sécurité critique (Protection anti-rétrogradation de l'Admin).
========================================================================================
"""

import requests
import sys

# URL de base de l'API FastAPI backend
BASE_URL = "http://localhost:8000/api/v1"

def test_auth_flow():
    """
    Exécute la séquence complète des tests d'authentification et de gestion des rôles.
    Lève une assertion en cas d'anomalie de sécurité.
    """

    # ----------------------------------------------------------------------------------
    # ÉTAPE 1 : Enregistrement des utilisateurs dans la base de données
    # ----------------------------------------------------------------------------------
    print("--- 1. Testing Registration ---")
    
    # Inscription du compte Administrateur système
    admin_reg = requests.post(f"{BASE_URL}/auth/register", json={
        "nom": "Admin",
        "prenom": "System",
        "email": "admin@phishguard.security",
        "password": "AdminPassword123!"
    })
    print("Admin Reg:", admin_reg.status_code, admin_reg.json().get("user"))

    # Inscription d'un compte Utilisateur Standard initial (Jean Dupont)
    std_reg = requests.post(f"{BASE_URL}/auth/register", json={
        "nom": "Dupont",
        "prenom": "Jean",
        "email": "jean.dupont@example.com",
        "password": "UserPassword123!"
    })
    print("Standard User Reg:", std_reg.status_code, std_reg.json().get("user"))

    # ----------------------------------------------------------------------------------
    # ÉTAPE 2 : Authentification et obtention du jeton d'accès JWT
    # ----------------------------------------------------------------------------------
    print("\n--- 2. Testing Login ---")
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "AdminPassword123!"
    })
    admin_token = login_resp.json().get("token")
    if not admin_token:
        # Tentative avec le mot de passe initial du seed officiel
        login_resp = requests.post(f"{BASE_URL}/auth/login", json={
            "email": "admin@phishguard.security",
            "password": "phishguard2026"
        })
        admin_token = login_resp.json().get("token")
    print("Admin Login Token:", bool(admin_token))

    # ----------------------------------------------------------------------------------
    # ÉTAPE 3 : Consultation de l'annuaire et promotion de rôle (RBAC)
    # ----------------------------------------------------------------------------------
    print("\n--- 3. Testing User Directory & Role Promotion ---")
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Récupération de la liste des utilisateurs enregistrés
    users_resp = requests.get(f"{BASE_URL}/users", headers=headers)
    print("Users list:", users_resp.status_code, [u["email"] + " (" + u["role"] + ")" for u in users_resp.json().get("users", [])])

    # Identification de l'utilisateur standard "jean.dupont@example.com"
    target_std = [u for u in users_resp.json().get("users", []) if u["email"] == "jean.dupont@example.com"][0]
    
    # Promotion de l'utilisateur standard au rôle "ENQUETEUR" (Analyste SOC)
    promote_resp = requests.patch(
        f"{BASE_URL}/users/{target_std['id']}/role",
        headers=headers,
        json={"new_role": "ENQUETEUR"}
    )
    print("Promote Standard -> Enquêteur:", promote_resp.status_code, promote_resp.json())

    # ----------------------------------------------------------------------------------
    # ÉTAPE 4 : Vérification du garde-fou de sécurité (Protection Administrateur)
    # Règle de conformité : Un compte Administrateur système ne peut être ni rétrogradé
    # ni altéré de façon arbitraire (doit retourner HTTP 403 Forbidden).
    # ----------------------------------------------------------------------------------
    print("\n--- 4. Testing Admin Protection Safeguard ---")
    admin_user = [u for u in users_resp.json().get("users", []) if u["email"] == "admin@phishguard.security"][0]
    demote_admin_resp = requests.patch(
        f"{BASE_URL}/users/{admin_user['id']}/role",
        headers=headers,
        json={"new_role": "UTILISATEUR_STANDARD"}
    )
    print("Attempting to modify Admin (Expect 403 Forbidden):", demote_admin_resp.status_code, demote_admin_resp.json())
    
    # Validation stricte du refus de sécurité 403
    assert demote_admin_resp.status_code == 403, "Admin safeguard failed!"
    print("SUCCESS: Admin Safeguard Rule verified!")

if __name__ == "__main__":
    test_auth_flow()
