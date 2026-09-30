import os
import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.database import engine, Base
import app.db.models
from app.db.mongodb import init_mongo_indexes
from app.api.v1 import analyze, monitor, incidents, verify, assistant, auth, users, ml_metrics, enterprise_security
from app.services.firewall_service import is_ip_blocked, get_blocked_ip_info
from fastapi import Request
from fastapi.responses import JSONResponse

# Initialize MongoDB connection & indexes
try:
    init_mongo_indexes()
except Exception as _e:
    print(f"[MongoDB Warning] Connection deferred: {_e}")

# Create DB Tables automatically
try:
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import text
    dialect = getattr(engine.dialect, "name", "sqlite").lower()
    ts_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
    if_not_exists = "IF NOT EXISTS " if dialect == "postgresql" else ""

    for table in ["utilisateurs_standards", "enqueteurs", "administrateurs"]:
        for col, col_type in [
            ("last_login", ts_type),
            ("password_raw", "VARCHAR(255)"),
            ("scan_count", "INTEGER DEFAULT 0"),
            ("report_count", "INTEGER DEFAULT 0")
        ]:
            try:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {if_not_exists}{col} {col_type}"))
            except Exception:
                pass
    try:
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE analysis_records ADD COLUMN {if_not_exists}user_id VARCHAR(36)"))
    except Exception:
        pass
except Exception as e:
    print(f"[Warning] Table creation deferred: {e}")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Enable CORS for Frontend Development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active Inline WAF Firewall Middleware
@app.middleware("http")
async def waf_active_firewall_middleware(request: Request, call_next):
    try:
        client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "127.0.0.1")
        if not request.url.path.startswith("/api/v1/enterprise/firewall") and not request.url.path.startswith("/docs"):
            if is_ip_blocked(client_ip):
                ban_info = get_blocked_ip_info(client_ip) or {}
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "ACCES_REFUSE_PAR_PARE_FEU_CYBERGUARD",
                        "status": "IP_BANNIE_PAR_WAF",
                        "client_ip": client_ip,
                        "reason": ban_info.get("reason", "Activité hostile interceptée par le WAF"),
                        "severity": ban_info.get("severity", "CRITICAL"),
                        "blocked_at": ban_info.get("blocked_at", ""),
                        "message": "Votre adresse IP a été bloquée par le pare-feu applicatif CyberGuard en raison de tentatives d'intrusion répétées."
                    }
                )
    except Exception:
        pass
    response = await call_next(request)
    return response

# Include Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)
app.include_router(analyze.router, prefix=settings.API_V1_STR)
app.include_router(monitor.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)
app.include_router(verify.router, prefix=settings.API_V1_STR)
app.include_router(assistant.router, prefix=settings.API_V1_STR)
app.include_router(ml_metrics.router, prefix=settings.API_V1_STR)
app.include_router(enterprise_security.router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    from app.db.mongodb import get_sync_db
    try:
        db = get_sync_db()
        mongo_status = "connected"
        collections = db.list_collection_names()
    except Exception as e:
        mongo_status = f"error: {e}"
        collections = []
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": {
            "type": "MongoDB",
            "status": mongo_status,
            "database_name": settings.MONGODB_DB_NAME,
            "collections_count": len(collections)
        },
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
