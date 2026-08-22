from app.db.database import Base, engine, SessionLocal
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, Incident, IncidentReport
from app.api.v1.auth import register_user, login_user, RegisterRequest, LoginRequest
from app.api.v1.users import update_user_role, RoleUpdateRequest
from app.api.v1.incidents import submit_user_report, UserScanReportRequest
from fastapi import HTTPException

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use isolated in-memory SQLite database for testing so PostgreSQL is never wiped or modified
test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=test_engine)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
db = TestSessionLocal()

def run_tests():
    print("=== PHISHGUARD 3 DISTINCT USER TABLES VERIFICATION ===")

    # Clear previous test data
    db.query(UtilisateurStandard).delete()
    db.query(Enqueteur).delete()
    db.query(Administrateur).delete()
    db.query(IncidentReport).delete()
    db.query(Incident).delete()
    db.commit()

    # 1. Register Admin (First user -> stored in 'administrateurs' table)
    admin_req = RegisterRequest(
        nom="System",
        prenom="Admin",
        email="admin@phishguard.security",
        password="AdminSecret123!"
    )
    admin_res = register_user(admin_req, db=db)
    admin_user_id = admin_res["user"]["id"]
    print("[1] Admin Registered in table:", admin_res["user"]["table"], "| Email:", admin_res["user"]["email"])
    assert admin_res["user"]["table"] == "administrateurs"

    # 2. Register Standard User (Second user -> stored in 'utilisateurs_standards' table)
    std_req = RegisterRequest(
        nom="Dupont",
        prenom="Jean",
        email="jean.dupont@example.com",
        password="UserSecret123!"
    )
    std_res = register_user(std_req, db=db)
    std_user_id = std_res["user"]["id"]
    print("[2] Standard User Registered in table:", std_res["user"]["table"], "| Email:", std_res["user"]["email"])
    assert std_res["user"]["table"] == "utilisateurs_standards"

    # 3. Login Check
    login_res = login_user(LoginRequest(email="jean.dupont@example.com", password="UserSecret123!"), db=db)
    print("[3] Login Successful from table:", login_res["user"]["table"])

    # 4. Standard User submits Phishing Scan Report
    report_req = UserScanReportRequest(
        title="Tentative d'usurpation de banque",
        target="http://examp1e-bank-login.xyz/auth",
        scan_type="URL",
        verdict="PHISHING",
        risk_score=88.5,
        details={"entropy": 4.8},
        reporter_name="Jean Dupont",
        reporter_email="jean.dupont@example.com"
    )
    rpt_res = submit_user_report(report_req, db=db)
    print("[4] Incident Report Submitted to Enquêteur Queue:", rpt_res["report"].report_code, "SHA-256 Digest:", rpt_res["integrity_hash"][:16] + "...")

    # 5. Admin promotes Standard User to ENQUETEUR (Transfers record from 'utilisateurs_standards' to 'enqueteurs')
    admin_obj = db.query(Administrateur).filter(Administrateur.id == admin_user_id).first()
    role_upd_req = RoleUpdateRequest(new_role="ENQUETEUR")
    upd_res = update_user_role(std_user_id, role_upd_req, current_user=admin_obj, db=db)
    print("[5] User Promoted & Transferred to table:", upd_res["user"]["table"])
    assert upd_res["user"]["table"] == "enqueteurs"

    # 6. ADMIN SAFEGUARD RULE: Attempt to demote/edit Admin account (Expect HTTP 403 Forbidden)
    print("[6] Testing Admin Safeguard Protection Rule...")
    try:
        update_user_role(admin_user_id, role_upd_req, current_user=admin_obj, db=db)
        print("FAIL: Safeguard did not trigger!")
        assert False, "Admin safeguard failed"
    except HTTPException as exc:
        print("SUCCESS: Admin Safeguard triggered HTTP 403 Forbidden!")
        print("    Detail:", exc.detail)
        assert exc.status_code == 403

    print("\n[OK] ALL 3 DISTINCT USER TABLES & WORKFLOW VERIFIED 100%!")

if __name__ == "__main__":
    run_tests()
