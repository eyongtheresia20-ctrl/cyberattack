from app.db.database import engine
from sqlalchemy import text

with engine.connect() as conn:
    version = conn.execute(text("SELECT version();")).scalar()
    db_name = conn.execute(text("SELECT current_database();")).scalar()
    total = conn.execute(text("SELECT COUNT(*) FROM analysis_records;")).scalar()
    phishing = conn.execute(text("SELECT COUNT(*) FROM analysis_records WHERE verdict = 'PHISHING';")).scalar()
    clean = conn.execute(text("SELECT COUNT(*) FROM analysis_records WHERE verdict = 'LÉGITIME';")).scalar()
    avg_conf = conn.execute(text("SELECT AVG(ml_confidence) FROM analysis_records;")).scalar()

    print("=== POSTGRESQL CONNECTION VERIFICATION ===")
    print("Dialect:", engine.dialect.name)
    print("Database Name:", db_name)
    print("Database Version:", version)
    print("------------------------------------------")
    print("Live Query Results from PostgreSQL:")
    print(" 1. Total Analyses (SELECT COUNT(*)):", total)
    print(" 2. Intercepted Threats (PHISHING):", phishing)
    print(" 3. Clean Analyses (LÉGITIME):", clean)
    print(" 4. ML Confidence (AVG):", avg_conf)
