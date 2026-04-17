from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, EmailStr
from app.db import otp_collection, users_collection
from app.rate_limiter import limiter
import random
import datetime
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(prefix="/verification", tags=["Verification"])

class OTPRequest(BaseModel):
    email: EmailStr

def send_otp_email(email: str, code: str):
    sender = os.getenv("GMAIL_SENDER", "")
    app_password = os.getenv("GMAIL_APP_PASSWORD", "")

    # Fallback si pas de credentials configurés → simulation console
    if not sender or not app_password or "votre.email" in sender:
        print(f"\n{'='*55}")
        print(f"📧 [SIMULATION] EMAIL DE VÉRIFICATION")
        print(f"   Destinataire : {email}")
        print(f"   Code OTP     : {code}")
        print(f"   Expiration   : 10 minutes")
        print(f"{'='*55}\n")
        return

    # Email HTML élégant
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔐 Votre code de vérification API Bank"
    msg["From"]    = sender
    msg["To"]      = email

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0f172a;margin:0;padding:20px;">
      <div style="max-width:420px;margin:auto;background:#1e293b;border-radius:12px;padding:32px;text-align:center;border:1px solid #334155;">
        <h1 style="color:#6366f1;margin-bottom:4px;">API Bank</h1>
        <p style="color:#94a3b8;font-size:14px;">Votre code de vérification</p>
        <div style="background:#0f172a;border-radius:10px;padding:20px;margin:24px 0;">
          <span style="font-size:2.5rem;font-weight:bold;letter-spacing:16px;color:#fff;">{code}</span>
        </div>
        <p style="color:#94a3b8;font-size:13px;">Ce code est valable <strong style="color:#f59e0b;">10 minutes</strong>.</p>
        <p style="color:#475569;font-size:11px;margin-top:20px;">Si vous n'avez pas demandé ce code, ignorez cet email.</p>
      </div>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, app_password)
            server.sendmail(sender, email, msg.as_string())
        print(f"✅ Email OTP envoyé avec succès à {email}")
    except Exception as e:
        # Fallback console si Gmail échoue
        print(f"⚠️ Erreur SMTP : {e}")
        print(f"📧 [FALLBACK] Code OTP pour {email} : {code}")

@router.post("/request-otp")
@limiter.limit("3/minute")
def request_otp(request: Request, data: OTPRequest, background_tasks: BackgroundTasks):

    # Sécurité anti-spam : refuser si l'email a déjà un compte
    if users_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="L'adresse e-mail a déjà un compte.")

    # Génération du code à 6 chiffres
    code = str(random.randint(100000, 999999))
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    # Upsert (remplacer si déjà existant)
    otp_collection.update_one(
        {"email": data.email},
        {"$set": {"code": code, "expires_at": expiration}},
        upsert=True
    )

    # Envoi asynchrone (ne bloque pas la réponse HTTP)
    background_tasks.add_task(send_otp_email, data.email, code)

    return {"message": "Code envoyé !"}

from app.security.auth import verify_token
from fastapi import Depends

@router.post("/request-auth-otp")
@limiter.limit("5/minute")
def request_auth_otp(request: Request, background_tasks: BackgroundTasks, user=Depends(verify_token)):
    email = user["sub"]
    
    code = str(random.randint(100000, 999999))
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    otp_collection.update_one(
        {"email": email},
        {"$set": {"code": code, "expires_at": expiration}},
        upsert=True
    )

    background_tasks.add_task(send_otp_email, email, code)

    return {"message": "Code OTP envoyé à votre adresse e-mail !"}
