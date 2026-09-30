import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

Base = declarative_base()

def get_engine():
    if settings.USE_SQLITE_FALLBACK:
        db_path = os.path.join(os.path.dirname(__file__), "..", "phishguard.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        sqlite_url = f"sqlite:///{os.path.abspath(db_path)}"
        return create_engine(sqlite_url, connect_args={"check_same_thread": False})
    
    try:
        engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, connect_args={"options": "-c timezone=utc"})
        # Test connection
        with engine.connect() as conn:
            pass
        return engine
    except Exception as e:
        print(f"[Warning] PostgreSQL connection failed: {e}. Falling back to SQLite.")
        db_path = os.path.join(os.path.dirname(__file__), "..", "phishguard.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        sqlite_url = f"sqlite:///{os.path.abspath(db_path)}"
        return create_engine(sqlite_url, connect_args={"check_same_thread": False})

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
