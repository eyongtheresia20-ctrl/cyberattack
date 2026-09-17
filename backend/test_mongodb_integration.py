import os
import sys
import uuid
from datetime import datetime, timezone

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.mongodb import get_sync_db, init_mongo_indexes, mongo_collections
from app.core.security import hash_password, verify_password, generate_sha256_hash

def test_mongodb():
    print("[1] Initializing MongoDB indexes...")
    init_mongo_indexes()
    db = get_sync_db()

    print("[2] Testing collection connectivity...")
    collections = db.list_collection_names()
    print(f"    Available collections: {collections}")
    assert len(collections) > 0, "No collections found in MongoDB!"

    print("[3] Testing User Document query...")
    admin = db["administrateurs"].find_one({"email": "admin@phishguard.security"})
    assert admin is not None, "Admin user document not found in MongoDB!"
    assert verify_password("phishguard2026", admin["hashed_password"]), "Admin password verification failed!"
    print(f"    Found Admin: {admin['email']} (Role: {admin.get('role')})")

    user = db["utilisateurs_standards"].find_one({"email": "alice.martin@example.com"})
    assert user is not None, "Standard user document not found in MongoDB!"
    print(f"    Found Standard User: {user['email']}")

    print("[4] Testing Analysis Record and SHA-256 Hash query...")
    analysis_count = db["analysis_records"].count_documents({})
    assert analysis_count > 0, "No analysis records found in MongoDB!"
    one_analysis = db["analysis_records"].find_one()
    print(f"    Found {analysis_count} analyses. Sample Code: {one_analysis.get('analysis_code')}, SHA-256: {one_analysis.get('integrity_hash')[:16]}...")

    print("[5] Testing Incident and Evidence collections...")
    incident_count = db["incidents"].count_documents({})
    assert incident_count > 0, "No incidents found in MongoDB!"
    one_incident = db["incidents"].find_one()
    print(f"    Found {incident_count} incidents. Sample: {one_incident.get('incident_code')} - {one_incident.get('title')}")

    print("\n[ALL TESTS PASSED] MongoDB database layer is fully operational and verified!")

if __name__ == "__main__":
    test_mongodb()
