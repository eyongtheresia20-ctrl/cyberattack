import requests
import sys

BASE_URL = "http://localhost:8000/api/v1"

def test_auth_flow():
    print("--- 1. Testing Registration ---")
    admin_reg = requests.post(f"{BASE_URL}/auth/register", json={
        "nom": "Admin",
        "prenom": "System",
        "email": "admin@phishguard.security",
        "password": "AdminPassword123!"
    })
    print("Admin Reg:", admin_reg.status_code, admin_reg.json().get("user"))

    std_reg = requests.post(f"{BASE_URL}/auth/register", json={
        "nom": "Dupont",
        "prenom": "Jean",
        "email": "jean.dupont@example.com",
        "password": "UserPassword123!"
    })
    print("Standard User Reg:", std_reg.status_code, std_reg.json().get("user"))

    print("\n--- 2. Testing Login ---")
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "admin@phishguard.security",
        "password": "AdminPassword123!"
    })
    admin_token = login_resp.json().get("token")
    print("Admin Login Token:", bool(admin_token))

    print("\n--- 3. Testing User Directory & Role Promotion ---")
    headers = {"Authorization": f"Bearer {admin_token}"}
    users_resp = requests.get(f"{BASE_URL}/users", headers=headers)
    print("Users list:", users_resp.status_code, [u["email"] + " (" + u["role"] + ")" for u in users_resp.json().get("users", [])])

    target_std = [u for u in users_resp.json().get("users", []) if u["email"] == "jean.dupont@example.com"][0]
    promote_resp = requests.patch(
        f"{BASE_URL}/users/{target_std['id']}/role",
        headers=headers,
        json={"new_role": "ENQUETEUR"}
    )
    print("Promote Standard -> Enquêteur:", promote_resp.status_code, promote_resp.json())

    print("\n--- 4. Testing Admin Protection Safeguard ---")
    admin_user = [u for u in users_resp.json().get("users", []) if u["email"] == "admin@phishguard.security"][0]
    demote_admin_resp = requests.patch(
        f"{BASE_URL}/users/{admin_user['id']}/role",
        headers=headers,
        json={"new_role": "UTILISATEUR_STANDARD"}
    )
    print("Attempting to modify Admin (Expect 403 Forbidden):", demote_admin_resp.status_code, demote_admin_resp.json())
    assert demote_admin_resp.status_code == 403, "Admin safeguard failed!"
    print("SUCCESS: Admin Safeguard Rule verified!")

if __name__ == "__main__":
    test_auth_flow()
