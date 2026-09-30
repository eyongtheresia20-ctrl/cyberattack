from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, AuditLog
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

class RegisterRequest(BaseModel):
    nom: str
    prenom: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class ProfileUpdateRequest(BaseModel):
    nom: str | None = None
    prenom: str | None = None
    email: str | None = None
    password: str | None = None
    current_password: str | None = None
    new_password: str | None = None

def find_user_by_email(email: str, db: Session):
    user = db.query(UtilisateurStandard).filter(UtilisateurStandard.email == email).first()
    if user:
        return user
    user = db.query(Enqueteur).filter(Enqueteur.email == email).first()
    if user:
        return user
    user = db.query(Administrateur).filter(Administrateur.email == email).first()
    return user

def find_user_by_id(user_id: str, db: Session):
    user = db.query(UtilisateurStandard).filter(UtilisateurStandard.id == user_id).first()
    if user:
        return user
    user = db.query(Enqueteur).filter(Enqueteur.id == user_id).first()
    if user:
        return user
    user = db.query(Administrateur).filter(Administrateur.id == user_id).first()
    return user

def get_optional_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if authorization:
        auth_str = authorization.strip()
        if auth_str.lower().startswith("bearer "):
            token = auth_str[7:].strip()
        else:
            token = auth_str
        payload = decode_access_token(token)
        if payload:
            user_id = payload.get("sub")
            if user_id:
                user = find_user_by_id(str(user_id), db)
                if user:
                    return user
            email = payload.get("email")
            if email:
                user = find_user_by_email(email, db)
                if user:
                    return user
    return None

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    user = get_optional_user(authorization, db)
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur non authentifié")

@router.post("/register", response_model=dict)
def register_user(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = find_user_by_email(req.email, db)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Un compte existe déjà avec cet email")
    
    total_users = (
        db.query(UtilisateurStandard).count() +
        db.query(Enqueteur).count() +
        db.query(Administrateur).count()
    )
    
    now = datetime.now(timezone.utc)
    if total_users == 0:
        user = Administrateur(
            nom=req.nom,
            prenom=req.prenom,
            email=req.email,
            hashed_password=hash_password(req.password),
            password_raw=req.password,
            role="ADMINISTRATEUR",
            last_login=now
        )
    else:
        user = UtilisateurStandard(
            nom=req.nom,
            prenom=req.prenom,
            email=req.email,
            hashed_password=hash_password(req.password),
            password_raw=req.password,
            role="UTILISATEUR_STANDARD",
            last_login=now
        )
        
    db.add(user)
    
    role_label = "Administrateur" if user.role == "ADMINISTRATEUR" else "Utilisateur Standard"
    audit = AuditLog(
        actor=f"{req.prenom} {req.nom}",
        action="REGISTER",
        target=user.email,
        details=f"Création de compte réussie ({role_label})"
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    # Persist to MongoDB
    try:
        from app.db.mongodb import mongo_collections, log_mongo_audit
        mongo_user_doc = {
            "id": user.id,
            "nom": user.nom,
            "prenom": user.prenom,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "password_raw": user.password_raw or req.password,
            "role": user.role,
            "scan_count": 0,
            "report_count": 0,
            "is_active": True,
            "created_at": now,
            "last_login": now
        }
        if user.role == "ADMINISTRATEUR":
            mongo_collections.admins.insert_one(mongo_user_doc)
        else:
            mongo_collections.users.insert_one(mongo_user_doc)
        log_mongo_audit(
            actor=f"{req.prenom} {req.nom}",
            action="REGISTER",
            target=user.email,
            details=f"Création de compte réussie ({role_label})",
            timestamp=now
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Register: {_me}")
    
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    
    return {
        "message": f"Compte créé avec succès dans la table {user.__tablename__}",
        "token": token,
        "user": {
            "id": user.id,
            "nom": user.nom,
            "prenom": user.prenom,
            "email": user.email,
            "role": user.role,
            "table": user.__tablename__,
            "scan_count": getattr(user, "scan_count", 0) or 0,
            "report_count": getattr(user, "report_count", 0) or 0,
            "last_login": user.last_login.isoformat() if getattr(user, "last_login", None) else now.isoformat(),
            "password": user.password_raw or req.password
        }
    }

@router.post("/login", response_model=dict)
def login_user(req: LoginRequest, db: Session = Depends(get_db)):
    user = find_user_by_email(req.email, db)
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou mot de passe incorrect")
    
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Compte désactivé")
    
    now = datetime.now(timezone.utc)
    user.last_login = now
    if not user.password_raw:
        user.password_raw = req.password
    
    role_label = (
        "Enquêteur SOC" if user.role == "ENQUETEUR"
        else ("Administrateur" if user.role == "ADMINISTRATEUR"
        else "Utilisateur Standard")
    )
    audit = AuditLog(
        actor=f"{user.prenom} {user.nom}",
        action="LOGIN",
        target=user.email,
        details=f"Connexion sécurisée au portail CyberGuard ({role_label})"
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    # Persist login & audit log to MongoDB
    try:
        from app.db.mongodb import update_mongo_user_login, log_mongo_audit
        update_mongo_user_login(user.id, now)
        log_mongo_audit(
            actor=f"{user.prenom} {user.nom}",
            action="LOGIN",
            target=user.email,
            details=f"Connexion sécurisée au portail CyberGuard ({role_label})",
            timestamp=now
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Login: {_me}")
    
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "nom": user.nom,
            "prenom": user.prenom,
            "email": user.email,
            "role": user.role,
            "table": user.__tablename__,
            "scan_count": getattr(user, "scan_count", 0) or 0,
            "report_count": getattr(user, "report_count", 0) or 0,
            "last_login": to_utc_iso(user.last_login) if getattr(user, "last_login", None) else now.isoformat(),
            "password": user.password_raw or req.password
        }
    }

def to_utc_iso(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        if not dt.endswith("Z") and not ("+" in dt[10:] or "-" in dt[10:]):
            return dt + "Z"
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

@router.get("/me", response_model=dict)
def get_me(current_user=Depends(get_current_user)):
    last_log = getattr(current_user, "last_login", None)
    return {
        "user": {
            "id": current_user.id,
            "nom": current_user.nom,
            "prenom": current_user.prenom,
            "email": current_user.email,
            "role": current_user.role,
            "table": current_user.__tablename__,
            "scan_count": getattr(current_user, "scan_count", 0) or 0,
            "report_count": getattr(current_user, "report_count", 0) or 0,
            "last_login": to_utc_iso(last_log) if last_log else datetime.now(timezone.utc).isoformat(),
            "password": getattr(current_user, "password_raw", None) or "User123!"
        }
    }

@router.put("/profile", response_model=dict)
def update_profile(
    req: ProfileUpdateRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if req.email and req.email.strip() != current_user.email:
        existing = find_user_by_email(req.email.strip(), db)
        if existing and existing.id != current_user.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Un autre compte utilise déjà cet e-mail.")
        current_user.email = req.email.strip()
        
    if req.nom and req.nom.strip():
        current_user.nom = req.nom.strip()
        
    if req.prenom and req.prenom.strip():
        current_user.prenom = req.prenom.strip()
        
    pwd = req.password or req.new_password
    if pwd and pwd.strip():
        current_user.hashed_password = hash_password(pwd.strip())
        current_user.password_raw = pwd.strip()

    audit = AuditLog(
        actor=f"{current_user.prenom} {current_user.nom}",
        action="UPDATE_PROFILE",
        target=current_user.email,
        details="Mise à jour des informations de profil et du mot de passe en base de données"
    )
    db.add(audit)
    db.commit()
    db.refresh(current_user)

    # Persist profile update and audit to MongoDB
    try:
        from app.db.mongodb import mongo_collections, log_mongo_audit
        update_fields = {
            "nom": current_user.nom,
            "prenom": current_user.prenom,
            "email": current_user.email,
            "hashed_password": current_user.hashed_password,
            "password_raw": current_user.password_raw
        }
        for col in [mongo_collections.users, mongo_collections.investigators, mongo_collections.admins]:
            col.update_one({"id": str(current_user.id)}, {"$set": update_fields})
        log_mongo_audit(
            actor=f"{current_user.prenom} {current_user.nom}",
            action="UPDATE_PROFILE",
            target=current_user.email,
            details="Mise à jour des informations de profil et du mot de passe en base de données"
        )
    except Exception as _me:
        print(f"[MongoDB Sync Warning] Profile: {_me}")
    
    last_log = getattr(current_user, "last_login", None)
    return {
        "message": "Profil et mot de passe mis à jour avec succès en base de données !",
        "user": {
            "id": current_user.id,
            "nom": current_user.nom,
            "prenom": current_user.prenom,
            "email": current_user.email,
            "role": current_user.role,
            "table": current_user.__tablename__,
            "last_login": last_log.isoformat() if last_log else datetime.now(timezone.utc).isoformat(),
            "password": current_user.password_raw or "User123!"
        }
    }

