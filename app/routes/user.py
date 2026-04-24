from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, EmailStr, field_validator
from werkzeug.security import generate_password_hash
from app.db import users_collection, otp_collection, accounts_collection, transactions_collection, beneficiaries_collection
from app.rate_limiter import limiter
import re
import datetime

router = APIRouter(prefix="/users", tags=["Users"])

# 🧑 modèle user enrichi (KYC)
class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    lastname: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z\s]+$")
    email: EmailStr
    cin: str = Field(..., pattern=r"^\d{8}$")
    phone: str = Field(None, pattern=r"^\+?[0-9]{8,15}$")
    password: str = Field(..., min_length=6, max_length=20)
    verification_code: str = Field(..., pattern=r"^\d{6}$")

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,20}$", v):
            raise ValueError("Mot de passe faible: nécessiste majuscule, minuscule, chiffre et symbole.")
        return v


# ➜ créer un utilisateur
@router.post("/")
@limiter.limit("5/minute")
def create_user(request: Request, user: User):

    # Unicité de l'identité (Email ou CIN)
    if users_collection.find_one({"$or": [{"email": user.email}, {"cin": user.cin}]}):
        raise HTTPException(status_code=400, detail="L'utilisateur (Email ou CIN) existe déjà.")

    # ✅ Vérification du code OTP
    otp_record = otp_collection.find_one({"email": user.email})
    if not otp_record:
        raise HTTPException(status_code=400, detail="Aucun code OTP généré pour cet email. Cliquez sur 'Envoyer le code'.")
    if datetime.datetime.utcnow() > otp_record["expires_at"]:
        otp_collection.delete_one({"email": user.email})
        raise HTTPException(status_code=400, detail="Code OTP expiré. Veuillez demander un nouveau code.")
        
    if otp_record["code"] != user.verification_code:
        failed_attempts = otp_record.get("failed_attempts", 0) + 1
        if failed_attempts >= 3:
            otp_collection.delete_one({"email": user.email})
            raise HTTPException(status_code=403, detail="Trop de tentatives echouees. Le code OTP a ete revoque. Veuillez en demander un nouveau.")
        else:
            otp_collection.update_one({"email": user.email}, {"$set": {"failed_attempts": failed_attempts}})
            raise HTTPException(status_code=400, detail="Code de vérification incorrect.")

    # transformer en dict
    new_user = user.dict()
    
    # ✂️ Ne pas stocker le code OTP en base !
    new_user.pop("verification_code", None)
    
    # Hachage sécurisé du mot de passe (sans erreur binaire Windows)
    new_user["password"] = generate_password_hash(user.password)

    # insertion dans MongoDB
    result = users_collection.insert_one(new_user)

    # 🗑️ Supprimer le code OTP : un seul usage autorisé (One-Time Password)
    otp_collection.delete_one({"email": user.email})

    return {
        "message": "User created successfully",
        "user_id": str(result.inserted_id)
    }

from app.security.auth import verify_token
from fastapi import Depends
from werkzeug.security import check_password_hash

def verify_auth_otp(email: str, otp_code: str):
    """Vérifie le code OTP pour une action sensible."""
    otp_record = otp_collection.find_one({"email": email})
    if not otp_record:
        raise HTTPException(status_code=400, detail="Aucun code OTP généré pour cet email.")
    if datetime.datetime.utcnow() > otp_record["expires_at"]:
        otp_collection.delete_one({"email": email})
        raise HTTPException(status_code=400, detail="Code OTP expiré. Veuillez en demander un nouveau.")
        
    if otp_record["code"] != otp_code:
        failed_attempts = otp_record.get("failed_attempts", 0) + 1
        if failed_attempts >= 3:
            otp_collection.delete_one({"email": email})
            raise HTTPException(status_code=403, detail="Trop de tentatives échouées. Code révoqué.")
        else:
            otp_collection.update_one({"email": email}, {"$set": {"failed_attempts": failed_attempts}})
            raise HTTPException(status_code=400, detail="Code de vérification incorrect.")
            
    # Valid
    otp_collection.delete_one({"email": email})
    return True

@router.get("/me")
def get_current_user(user=Depends(verify_token)):
    db_user = users_collection.find_one({"email": user["sub"]})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    
    return {
        "username": db_user.get("username"),
        "lastname": db_user.get("lastname"),
        "email": db_user.get("email"),
        "cin": db_user.get("cin"),
        "phone": db_user.get("phone")
    }

class SettingsUpdate(BaseModel):
    current_password: str
    otp_code: str
    new_username: str = None
    new_lastname: str = None
    new_password: str = None

class ContactUpdate(BaseModel):
    current_password: str
    otp_code: str
    new_email: str = Field(None, description="Nouvel email")
    new_phone: str = Field(None, pattern=r"^\+?[0-9]{8,15}$")

class UserDelete(BaseModel):
    current_password: str
    otp_code: str

@router.put("/me/security")
@limiter.limit("5/minute")
def update_security_settings(request: Request, data: SettingsUpdate, user=Depends(verify_token)):
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # 1. Vérification du mot de passe
    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    # 2. Vérification de l'OTP
    verify_auth_otp(email, data.otp_code)

    # 3. Application des modifications
    updates = {}
    if data.new_username:
        updates["username"] = data.new_username
    if data.new_lastname:
        updates["lastname"] = data.new_lastname
    if data.new_password:
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,20}$", data.new_password):
            raise HTTPException(status_code=400, detail="Le nouveau mot de passe est trop faible.")
        updates["password"] = generate_password_hash(data.new_password)

    if updates:
        users_collection.update_one({"email": email}, {"$set": updates})

    return {"message": "Paramètres mis à jour avec succès"}

@router.post("/me/delete")
@limiter.limit("2/minute")
def delete_user_profile(request: Request, data: UserDelete, user=Depends(verify_token)):
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # 1. Vérification du mot de passe
    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    # 2. Vérification de l'OTP
    verify_auth_otp(email, data.otp_code)

    user_id = str(db_user["_id"])

    # 3. Nettoyage complet
    # Suppression des bénéficiaires
    beneficiaries_collection.delete_many({"owner_id": user_id})
    
    # Suppression des transactions (pour tous les comptes de cet utilisateur)
    transactions_collection.delete_many({"owner_id": user_id})
    
    # Suppression des comptes bancaires
    accounts_collection.delete_many({"owner_id": user_id})
    
    # Suppression de l'utilisateur
    users_collection.delete_one({"_id": db_user["_id"]})

    # Log - On le fait avant de supprimer l'utilisateur si on veut garder une trace liée à son ID 
    # ou on log l'action de manière générale.
    from app.security.logger import log_activity
    log_activity(user_id, "N/A", "USER_PROFILE_DELETION", "SUCCESS", {"email": email})

    return {"message": "Profil utilisateur et toutes les données associées supprimés avec succès."}

@router.put("/me/contact")
@limiter.limit("3/minute")
def update_contact_info(request: Request, data: ContactUpdate, user=Depends(verify_token)):
    """Met à jour l'email et/ou le numéro de téléphone de l'utilisateur."""
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # 1. Vérification mot de passe
    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    # 2. Vérification OTP
    verify_auth_otp(email, data.otp_code)

    updates = {}
    if data.new_email:
        # Vérifier que le nouvel email n'est pas déjà utilisé
        if users_collection.find_one({"email": data.new_email}):
            raise HTTPException(status_code=400, detail="Cet email est déjà utilisé par un autre compte.")
        updates["email"] = data.new_email
    if data.new_phone:
        updates["phone"] = data.new_phone

    if not updates:
        raise HTTPException(status_code=400, detail="Aucune modification fournie.")

    users_collection.update_one({"email": email}, {"$set": updates})

    from app.security.logger import log_activity
    log_activity(str(db_user["_id"]), "N/A", "CONTACT_UPDATE", "SUCCESS", {"fields": list(updates.keys())})

    return {"message": "Coordonnées mises à jour avec succès.", "updated": list(updates.keys())}