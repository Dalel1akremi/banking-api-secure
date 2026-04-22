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
    password: str = Field(..., min_length=6, max_length=100)

class Verify2FA(BaseModel):
    email: EmailStr
    otp_code: str

import datetime

@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: Login, background_tasks: BackgroundTasks):

    db_user = users_collection.find_one({"email": user.email})

    if db_user:
        locked_until = db_user.get("locked_until")
        if locked_until and datetime.datetime.utcnow() < locked_until:
            raise HTTPException(status_code=403, detail="Compte verrouille suite a trop de tentatives echouees. Reesayez dans 15 minutes.")

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
                update_data["locked_until"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            users_collection.update_one({"_id": db_user["_id"]}, {"$set": update_data})

        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Reinitialiser les tentatives si succes
    if db_user.get("failed_login_attempts", 0) > 0 or db_user.get("locked_until"):
        users_collection.update_one({"_id": db_user["_id"]}, {"$unset": {"locked_until": ""}, "$set": {"failed_login_attempts": 0}})

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