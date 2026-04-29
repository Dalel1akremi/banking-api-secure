from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field, EmailStr, field_validator
from werkzeug.security import generate_password_hash, check_password_hash
from app.db import users_collection, otp_collection, accounts_collection, transactions_collection, beneficiaries_collection
from app.rate_limiter import limiter
from app.security.auth import verify_token
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
    new_user.pop("verification_code", None)
    new_user["password"] = generate_password_hash(user.password)

    # insertion dans MongoDB
    result = users_collection.insert_one(new_user)
    otp_collection.delete_one({"email": user.email})

    return {
        "message": "User created successfully",
        "user_id": str(result.inserted_id)
    }

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
        "phone": db_user.get("phone"),
        "biometric_enabled": bool(db_user.get("biometric_credential_id"))
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

    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    verify_auth_otp(email, data.otp_code)

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

    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    verify_auth_otp(email, data.otp_code)

    user_id = str(db_user["_id"])
    beneficiaries_collection.delete_many({"owner_id": user_id})
    transactions_collection.delete_many({"owner_id": user_id})
    accounts_collection.delete_many({"owner_id": user_id})
    users_collection.delete_one({"_id": db_user["_id"]})

    from app.security.logger import log_activity
    log_activity(user_id, "N/A", "USER_PROFILE_DELETION", "SUCCESS", {"email": email})

    return {"message": "Profil utilisateur et toutes les données associées supprimés avec succès."}

@router.put("/me/contact")
@limiter.limit("3/minute")
def update_contact_info(request: Request, data: ContactUpdate, user=Depends(verify_token)):
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    verify_auth_otp(email, data.otp_code)

    updates = {}
    if data.new_email:
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

class BiometricRegister(BaseModel):
    credential_id: str

def euclidean_distance(v1, v2):
    return sum((a - b) ** 2 for a, b in zip(v1, v2)) ** 0.5

@router.post("/me/biometric/register")
@limiter.limit("5/minute")
def register_biometric(request: Request, data: BiometricRegister, user=Depends(verify_token)):
    import json
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # --- VÉRIFICATION D'UNICITÉ ---
    try:
        new_descriptor = json.loads(data.credential_id)
    except:
        raise HTTPException(status_code=400, detail="Format de signature invalide")

    # On cherche si ce visage appartient déjà à quelqu'un d'autre
    other_users = users_collection.find({
        "email": {"$ne": email}, 
        "biometric_credential_id": {"$exists": True}
    })
    
    for other in other_users:
        try:
            stored_desc = json.loads(other["biometric_credential_id"])
            dist = euclidean_distance(new_descriptor, stored_desc)
            if dist < 0.7:
                raise HTTPException(
                    status_code=400, 
                    detail="Ce visage est déjà associé à un autre compte bancaire."
                )
        except HTTPException: raise
        except: continue
    # ------------------------------

    users_collection.update_one({"email": email}, {"$set": {"biometric_credential_id": data.credential_id}})

    from app.security.logger import log_activity
    log_activity(str(db_user["_id"]), "N/A", "BIOMETRIC_REGISTER", "SUCCESS", {})

    return {"message": "Authentification biométrique activée avec succès."}

@router.delete("/me/biometric")
@limiter.limit("5/minute")
def deactivate_biometric(request: Request, user=Depends(verify_token)):
    email = user["sub"]
    users_collection.update_one({"email": email}, {"$unset": {"biometric_credential_id": ""}})
    return {"message": "Authentification biométrique désactivée"}