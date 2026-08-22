from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.db.models import UtilisateurStandard, Enqueteur, Administrateur, AuditLog
from app.api.v1.auth import get_current_user, find_user_by_id

router = APIRouter(prefix="/users", tags=["User Management"])

class RoleUpdateRequest(BaseModel):
    new_role: str # UTILISATEUR_STANDARD or ENQUETEUR

@router.get("", response_model=dict)
def list_users(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")
    
    stds = db.query(UtilisateurStandard).all()
    enqs = db.query(Enqueteur).all()
    adms = db.query(Administrateur).all()
    
    user_list = []
    for u in stds:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "utilisateurs_standards", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    for u in enqs:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "enqueteurs", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    for u in adms:
        user_list.append({
            "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
            "role": u.role, "table": "administrateurs", "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
        
    return {"users": user_list, "total": len(user_list)}

@router.patch("/{user_id}/role", response_model=dict)
def update_user_role(
    user_id: str,
    req: RoleUpdateRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "ADMINISTRATEUR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès réservé aux Administrateurs")
    
    target_user = find_user_by_id(user_id, db)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")
    
    # ADMIN SAFEGUARD RULE: An Admin CANNOT edit, demote, or delete another Admin account
    if target_user.role == "ADMINISTRATEUR" or isinstance(target_user, Administrateur):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Protégé : Les comptes Administrateur ne peuvent pas être modifiés ou rétrogradés."
        )
        
    if req.new_role not in ["UTILISATEUR_STANDARD", "ENQUETEUR"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rôle invalide. Seuls UTILISATEUR_STANDARD et ENQUETEUR sont attribuables."
        )
        
    old_role = target_user.role
    
    # If role changed, move record between distinct tables
    if req.new_role == "ENQUETEUR" and not isinstance(target_user, Enqueteur):
        new_user = Enqueteur(
            id=target_user.id,
            nom=target_user.nom,
            prenom=target_user.prenom,
            email=target_user.email,
            hashed_password=target_user.hashed_password,
            role="ENQUETEUR",
            badge_number=f"SOC-{target_user.id[:8]}"
        )
        db.delete(target_user)
        db.add(new_user)
        target_user = new_user
    elif req.new_role == "UTILISATEUR_STANDARD" and not isinstance(target_user, UtilisateurStandard):
        new_user = UtilisateurStandard(
            id=target_user.id,
            nom=target_user.nom,
            prenom=target_user.prenom,
            email=target_user.email,
            hashed_password=target_user.hashed_password,
            role="UTILISATEUR_STANDARD"
        )
        db.delete(target_user)
        db.add(new_user)
        target_user = new_user

    audit = AuditLog(
        actor=f"{current_user.prenom} {current_user.nom}",
        action="UPDATE_USER_ROLE",
        target=target_user.email,
        details=f"Changement de rôle et transfert de table : {old_role} -> {req.new_role}"
    )
    db.add(audit)
    db.commit()
    
    return {
        "message": f"Rôle mis à jour avec succès en {target_user.role} dans la table {target_user.__tablename__}",
        "user": {
            "id": target_user.id,
            "email": target_user.email,
            "role": target_user.role,
            "table": target_user.__tablename__
        }
    }
