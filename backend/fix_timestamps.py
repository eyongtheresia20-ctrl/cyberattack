import os
import sys
from datetime import datetime, timezone, timedelta

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.mongodb import get_sync_db
from app.db.database import SessionLocal
from app.db.models import AnalysisRecord, AuditLog

def fix_all_timestamps():
    db_mongo = get_sync_db()
    db_sql = SessionLocal()
    utc_now = datetime.now(timezone.utc).replace(tzinfo=None)

    print(f"Current true UTC threshold: {utc_now}")

    # 1. MongoDB analysis_records
    for a in db_mongo["analysis_records"].find():
        ts = a.get("created_at")
        if ts and ts > utc_now:
            # Shift by -1 hour to correct local-time insertion to UTC
            new_ts = ts - timedelta(hours=1)
            db_mongo["analysis_records"].update_one(
                {"_id": a["_id"]},
                {"$set": {"created_at": new_ts}}
            )
            print(f"[Mongo Analysis Fixed] {a.get('analysis_code')}: {ts} -> {new_ts}")

    # 2. MongoDB audit_logs
    for l in db_mongo["audit_logs"].find():
        ts = l.get("timestamp")
        if ts and ts > utc_now:
            new_ts = ts - timedelta(hours=1)
            db_mongo["audit_logs"].update_one(
                {"_id": l["_id"]},
                {"$set": {"timestamp": new_ts}}
            )
            print(f"[Mongo Audit Fixed] {l.get('id')}: {ts} -> {new_ts}")

    # 3. MongoDB user last_logins
    for col in ["administrateurs", "enqueteurs", "utilisateurs_standards"]:
        for u in db_mongo[col].find():
            ts = u.get("last_login")
            if ts and ts > utc_now:
                new_ts = ts - timedelta(hours=1)
                db_mongo[col].update_one(
                    {"_id": u["_id"]},
                    {"$set": {"last_login": new_ts}}
                )
                print(f"[Mongo User Fixed] {u.get('email')}: {ts} -> {new_ts}")

    # 4. SQLite analysis_records
    for a in db_sql.query(AnalysisRecord).all():
        if a.created_at and a.created_at > utc_now:
            orig = a.created_at
            a.created_at = a.created_at - timedelta(hours=1)
            print(f"[SQL Analysis Fixed] {a.analysis_code}: {orig} -> {a.created_at}")

    # 5. SQLite audit_logs
    for l in db_sql.query(AuditLog).all():
        if l.timestamp and l.timestamp > utc_now:
            orig = l.timestamp
            l.timestamp = l.timestamp - timedelta(hours=1)
            print(f"[SQL Audit Fixed] {l.id}: {orig} -> {l.timestamp}")

    db_sql.commit()
    print("All future/misaligned timestamps successfully corrected to UTC!")

if __name__ == "__main__":
    fix_all_timestamps()
