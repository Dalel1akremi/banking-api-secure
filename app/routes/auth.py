from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, EmailStr
from app.security.auth import create_access_token
from app.db import users_collection, otp_collection
from app.rate_limiter import limiter
from werkzeug.security import check_password_hash
from fastapi import BackgroundTasks
import random
from app.routes.email_verification import send_otp_email

router = APIRouter(prefix="/auth", tags=["Auth"])

class Login(BaseModel):
    email: EmailStr
    password: str

class Verify2FA(BaseModel):
    email: EmailStr
    otp_code: str

import datetime

@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: Login, background_tasks: BackgroundTasks):

    db_user = users_collection.find_one({"email": user.email})

    if db_user:
        # ✅ Vérification du statut du compte (bloqué par l'admin ou après brute force)
        user_status = db_user.get("status", "active")
        if user_status == "blocked":
            raise HTTPException(
                status_code=403,
                detail="Votre compte est bloqué. Veuillez contacter l'administrateur pour le débloquer."
            )

    db_password = db_user.get("password", "") if db_user else ""
    try:
        is_valid = check_password_hash(db_password, user.password)
    except Exception:
        is_valid = False

    if not db_user or not is_valid:
        if db_user:
            failed_attempts = db_user.get("failed_login_attempts", 0) + 1
            update_data = {"failed_login_attempts": failed_attempts}
            if failed_attempts >= 3:
                # ✅ Blocage permanent jusqu'à intervention de l'administrateur
                update_data["status"] = "blocked"
            users_collection.update_one({"_id": db_user["_id"]}, {"$set": update_data})

        # Set target email for the middleware to log
        request.state.target_email = user.email
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Reinitialiser les tentatives si succes
    if db_user.get("failed_login_attempts", 0) > 0:
        users_collection.update_one(
            {"_id": db_user["_id"]},
            {"$set": {"failed_login_attempts": 0}}
        )

    # Gen OTP for 2FA
    code = str(random.randint(100000, 999999))
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    
    otp_collection.update_one(
        {"email": user.email},
        {"$set": {"code": code, "expires_at": expiration}},
        upsert=True
    )
    
    background_tasks.add_task(send_otp_email, user.email, code)

    return {
        "require_otp": True,
        "message": "Veuillez vérifier votre email pour le code OTP.",
        "email": user.email
    }

@router.post("/verify-2fa")
@limiter.limit("5/minute")
def verify_login_2fa(request: Request, data: Verify2FA):
    db_user = users_collection.find_one({"email": data.email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email")
        
    otp_record = otp_collection.find_one({"email": data.email})
    if not otp_record:
        raise HTTPException(status_code=400, detail="Aucun code OTP généré pour cet email.")
    if datetime.datetime.utcnow() > otp_record["expires_at"]:
        otp_collection.delete_one({"email": data.email})
        raise HTTPException(status_code=400, detail="Code OTP expiré.")
        
    if otp_record["code"] != data.otp_code:
        failed_attempts = otp_record.get("failed_attempts", 0) + 1
        if failed_attempts >= 3:
            otp_collection.delete_one({"email": data.email})
            raise HTTPException(status_code=403, detail="Trop de tentatives. Code révoqué.")
        else:
            otp_collection.update_one({"email": data.email}, {"$set": {"failed_attempts": failed_attempts}})
            raise HTTPException(status_code=400, detail="Code de vérification incorrect.")
            
    # Valid! Issue tokens
    otp_collection.delete_one({"email": data.email})
    
    is_admin = db_user.get("is_admin", False)
    token = create_access_token({"sub": db_user["email"], "id": str(db_user["_id"]), "is_admin": is_admin})
    return {
        "access_token": token,
        "token_type": "bearer"
    }

from typing import Optional

class BiometricLogin(BaseModel):
    email: Optional[EmailStr] = None
    credential_id: str # This is now the JSON string of the face descriptor

def euclidean_distance(v1, v2):
    return sum((a - b) ** 2 for a, b in zip(v1, v2)) ** 0.5

@router.post("/login/biometric")
@limiter.limit("5/minute")
def login_biometric(request: Request, data: BiometricLogin):
    import json
    try:
        current_descriptor = json.loads(data.credential_id)
    except:
        raise HTTPException(status_code=400, detail="Format de signature faciale invalide")

    # Mode 1: Recherche par e-mail
    if data.email:
        db_user = users_collection.find_one({"email": data.email})
        if not db_user:
            raise HTTPException(status_code=401, detail="Aucun compte associé à cet email")
        
        stored_desc_raw = db_user.get("biometric_credential_id")
        if not stored_desc_raw:
            raise HTTPException(status_code=403, detail="Face ID n'est pas activé pour ce compte")
        
        try:
            stored_descriptor = json.loads(stored_desc_raw)
            dist = euclidean_distance(current_descriptor, stored_descriptor)
            # Seuil de reconnaissance assoupli à 0.7 pour plus de fiabilité
            if dist > 0.7:
                raise HTTPException(
                    status_code=401, 
                    detail="Visage non reconnu (Écart de ressemblance: {:.2f}, max autorisé: 0.70)".format(dist)
                )
        except HTTPException: raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Erreur de lecture de la signature: " + str(e))

    # Mode 2: Identification automatique (One-Click Face ID)
    else:
        # On parcourt les utilisateurs ayant FaceID activé
        all_users = users_collection.find({"biometric_credential_id": {"$exists": True}})
        best_match = None
        min_dist = 2.0 
        
        for u in all_users:
            try:
                stored_desc = json.loads(u["biometric_credential_id"])
                dist = euclidean_distance(current_descriptor, stored_desc)
                if dist < min_dist:
                    min_dist = dist
                    if dist < 0.7:
                        best_match = u
            except: continue
            
        if not best_match:
            detail_msg = "Identité non reconnue"
            if min_dist < 2.0:
                detail_msg += " (Écart le plus proche: {:.2f}, max: 0.70)".format(min_dist)
            raise HTTPException(status_code=401, detail=detail_msg)
        
        db_user = best_match
        dist = min_dist # pour le log

    # Success! Create token
    # ✅ Vérifier le statut du compte avant d'accorder l'accès biométrique
    user_status = db_user.get("status", "active")
    if user_status == "blocked":
        raise HTTPException(
            status_code=403,
            detail="Votre compte est bloqué. Veuillez contacter l'administrateur pour le débloquer."
        )

    is_admin = db_user.get("is_admin", False)
    token = create_access_token({"sub": db_user["email"], "id": str(db_user["_id"]), "is_admin": is_admin})
    
    from app.security.logger import log_activity
    log_activity(str(db_user["_id"]), "N/A", "BIOMETRIC_LOGIN", "SUCCESS", {"distance": min_dist if not data.email else dist})

    return {
        "access_token": token,
        "token_type": "bearer",
        "message": "Connexion Face ID réussie"
    }

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str = Field(..., min_length=6, max_length=100)

@router.post("/forgot-password")
@limiter.limit("10/hour")
def forgot_password(request: Request, data: ForgotPassword, background_tasks: BackgroundTasks):
    db_user = users_collection.find_one({"email": data.email})
    if not db_user:
        # On ne révèle pas si l'email existe pour des raisons de sécurité
        return {"message": "Si votre e-mail existe dans notre système, vous recevrez un code de réinitialisation."}
        
    code = str(random.randint(100000, 999999))
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    
    # Stocker dans otp_collection avec un tag spécial
    otp_collection.update_one(
        {"email": data.email},
        {"$set": {"reset_code": code, "reset_expires_at": expiration}},
        upsert=True
    )
    
    # Envoyer l'email
    subject = "Réinitialisation de votre mot de passe"
    body = f"Votre code de réinitialisation est : <b>{code}</b>. Il expire dans 15 minutes."
    background_tasks.add_task(send_otp_email, data.email, code) # On réutilise la fonction d'envoi d'OTP
    
    return {"message": "Si votre e-mail existe dans notre système, vous recevrez un code de réinitialisation."}

from werkzeug.security import generate_password_hash

@router.post("/reset-password")
@limiter.limit("5/hour")
def reset_password(request: Request, data: ResetPassword):
    otp_record = otp_collection.find_one({"email": data.email})
    if not otp_record or "reset_code" not in otp_record:
        raise HTTPException(status_code=400, detail="Aucune demande de réinitialisation trouvée.")
        
    if datetime.datetime.utcnow() > otp_record["reset_expires_at"]:
        otp_collection.delete_one({"email": data.email})
        raise HTTPException(status_code=400, detail="Code expiré.")
        
    if otp_record["reset_code"] != data.otp_code:
        raise HTTPException(status_code=400, detail="Code de réinitialisation incorrect.")
        
    # Valid! Update password
    hashed_password = generate_password_hash(data.new_password)
    users_collection.update_one({"email": data.email}, {"$set": {"password": hashed_password}})
    otp_collection.delete_one({"email": data.email})
    
    return {"message": "Votre mot de passe a été réinitialisé avec succès."}