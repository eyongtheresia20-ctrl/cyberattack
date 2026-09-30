import os
import uuid
from datetime import datetime, timezone
from pymongo import MongoClient, ASCENDING
import motor.motor_asyncio
from app.core.config import settings

_sync_client = None
_sync_db = None
_async_client = None
_async_db = None

def get_sync_mongo_client() -> MongoClient:
    global _sync_client
    if _sync_client is None:
        _sync_client = MongoClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=3000,
            uuidRepresentation='standard'
        )
    return _sync_client

def get_sync_db():
    global _sync_db
    if _sync_db is None:
        client = get_sync_mongo_client()
        _sync_db = client[settings.MONGODB_DB_NAME]
    return _sync_db

def get_async_mongo_client() -> motor.motor_asyncio.AsyncIOMotorClient:
    global _async_client
    if _async_client is None:
        _async_client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=3000,
            uuidRepresentation='standard'
        )
    return _async_client

def get_async_db():
    global _async_db
    if _async_db is None:
        client = get_async_mongo_client()
        _async_db = client[settings.MONGODB_DB_NAME]
    return _async_db

def init_mongo_indexes():
    """Create essential unique and lookup indexes in MongoDB."""
    try:
        db = get_sync_db()
        db["utilisateurs_standards"].create_index([("email", ASCENDING)], unique=True)
        db["enqueteurs"].create_index([("email", ASCENDING)], unique=True)
        db["administrateurs"].create_index([("email", ASCENDING)], unique=True)
        db["analysis_records"].create_index([("analysis_code", ASCENDING)], unique=True)
        db["analysis_records"].create_index([("user_id", ASCENDING)])
        db["analysis_records"].create_index([("created_at", ASCENDING)])
        db["incidents"].create_index([("incident_code", ASCENDING)], unique=True)
        db["incident_reports"].create_index([("report_code", ASCENDING)], unique=True)
        db["incident_reports"].create_index([("incident_id", ASCENDING)])
        db["evidences"].create_index([("incident_id", ASCENDING)])
        db["security_events"].create_index([("timestamp", ASCENDING)])
        db["audit_logs"].create_index([("timestamp", ASCENDING)])
        db["ai_chat_messages"].create_index([("user_email", ASCENDING)])
        db["ai_chat_messages"].create_index([("created_at", ASCENDING)])
        print(f"[MongoDB] Successfully connected and initialized indexes on database '{settings.MONGODB_DB_NAME}'")
    except Exception as e:
        print(f"[MongoDB Warning] Index creation error: {e}")

class MongoDBCollections:
    @property
    def users(self):
        return get_sync_db()["utilisateurs_standards"]
    @property
    def investigators(self):
        return get_sync_db()["enqueteurs"]
    @property
    def admins(self):
        return get_sync_db()["administrateurs"]
    @property
    def analyses(self):
        return get_sync_db()["analysis_records"]
    @property
    def events(self):
        return get_sync_db()["security_events"]
    @property
    def incidents(self):
        return get_sync_db()["incidents"]
    @property
    def evidences(self):
        return get_sync_db()["evidences"]
    @property
    def reports(self):
        return get_sync_db()["incident_reports"]
    @property
    def audit_logs(self):
        return get_sync_db()["audit_logs"]
    @property
    def chat_messages(self):
        return get_sync_db()["ai_chat_messages"]

mongo_collections = MongoDBCollections()

def log_mongo_audit(actor: str, action: str, target: str, details: str, timestamp=None):
    """Save an audit log event into MongoDB cyberguard_db.audit_logs collection."""
    try:
        ts = timestamp or datetime.now(timezone.utc)
        if hasattr(ts, "tzinfo") and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        doc = {
            "id": str(uuid.uuid4()),
            "actor": actor or "Système",
            "action": action,
            "target": target or "-",
            "details": details or "",
            "timestamp": ts
        }
        mongo_collections.audit_logs.insert_one(doc)
        return doc
    except Exception as e:
        print(f"[MongoDB Audit Warning] Could not save audit log: {e}")
        return None

def find_mongo_user_by_email(email: str):
    """Find user document across all 3 MongoDB user collections."""
    if not email:
        return None
    for col in [mongo_collections.users, mongo_collections.investigators, mongo_collections.admins]:
        doc = col.find_one({"email": email})
        if doc:
            return doc
    return None

def find_mongo_user_by_id(user_id: str):
    """Find user document by id across all 3 MongoDB user collections."""
    if not user_id:
        return None
    for col in [mongo_collections.users, mongo_collections.investigators, mongo_collections.admins]:
        doc = col.find_one({"id": str(user_id)})
        if doc:
            return doc
    return None

def update_mongo_user_login(user_id: str, last_login_time=None):
    """Update last_login timestamp in MongoDB."""
    ts = last_login_time or datetime.now(timezone.utc)
    for col in [mongo_collections.users, mongo_collections.investigators, mongo_collections.admins]:
        res = col.update_one({"id": str(user_id)}, {"$set": {"last_login": ts}})
        if res.matched_count > 0:
            return True
    return False

def increment_mongo_user_scans(user_id: str):
    """Increment user scan counter in MongoDB."""
    if not user_id:
        return
    for col in [mongo_collections.users, mongo_collections.investigators, mongo_collections.admins]:
        res = col.update_one({"id": str(user_id)}, {"$inc": {"scan_count": 1}})
        if res.matched_count > 0:
            return

