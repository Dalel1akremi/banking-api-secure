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



def send_admin_action_email(target_email: str, target_name: str, action: str, reason: str, admin_info: dict):
    sender = os.getenv("GMAIL_SENDER", "")
    app_password = os.getenv("GMAIL_APP_PASSWORD", "")
    
    action_labels = {
        "blocked": "Blocage de sécurité",
        "active": "Réactivation de compte",
        "deactivated": "Suspension de carte"
    }
    
    subject = f"🔐 Alerte Sécurité - {action_labels.get(action, 'Mise à jour de profil')}"
    now_str = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")
    
    admin_name = admin_info.get("name", "Administrateur")
    admin_lastname = admin_info.get("lastname", "")
    admin_email = admin_info.get("email", "")

    # Fallback simulation
    if not sender or not app_password or "votre.email" in sender:
        print(f"\n{'='*60}")
        print(f"📧 [SIMULATION] EMAIL DE SÉCURITÉ ENRICHI")
        print(f"   Destinataire : {target_email}")
        print(f"   Action       : {action_labels.get(action, action)}")
        print(f"   Motif        : {reason}")
        print(f"   Date         : {now_str}")
        print(f"   Par          : {admin_name} {admin_lastname} ({admin_email})")
        print(f"{'='*60}\n")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = target_email

    html = f"""
    <html><body style="font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#0f172a;margin:0;padding:20px;">
      <div style="max-width:550px;margin:auto;background:#1e293b;border-radius:16px;padding:40px;border:1px solid #334155;box-shadow:0 10px 25px rgba(0,0,0,0.5);">
        <div style="text-align:center;margin-bottom:30px;">
            <h1 style="color:#fbbf24;margin:0;font-size:28px;letter-spacing:1px;">API BANK</h1>
            <p style="color:#64748b;font-size:12px;text-transform:uppercase;margin-top:5px;">Département de la Sécurité des Flux</p>
        </div>
        
        <h2 style="color:#fff;font-size:20px;border-bottom:1px solid #334155;padding-bottom:15px;">Avis de modification de statut</h2>
        
        <p style="color:#cbd5e1;line-height:1.6;">Bonjour <strong>{target_name}</strong>,</p>
        <p style="color:#cbd5e1;line-height:1.6;">Nous vous informons qu'une mesure de protection a été appliquée sur votre espace bancaire le <strong>{now_str}</strong>.</p>
        
        <div style="background:rgba(251,191,36,0.1);border-radius:12px;padding:25px;margin:30px 0;border-left:5px solid #fbbf24;">
          <p style="color:#fff;margin:0 0 10px 0;font-size:16px;"><strong>Détails de l'opération :</strong></p>
          <p style="color:#fbbf24;margin:5px 0;"><strong>Type :</strong> {action_labels.get(action, action.upper())}</p>
          <p style="color:#cbd5e1;margin:5px 0;"><strong>Motif :</strong> {reason.replace('le conseiller référent', admin_name + ' ' + admin_lastname) if 'le conseiller référent' in reason else reason}</p>
        </div>

        <div style="margin:30px 0;">
            <p style="color:#94a3b8;font-size:13px;margin-bottom:10px;">Opération traitée par votre conseiller référent :</p>
            <div style="background:#0f172a;padding:15px;border-radius:8px;">
                <p style="color:#fff;margin:0;font-size:15px;"><strong>{admin_name} {admin_lastname}</strong></p>
                <p style="color:#6366f1;margin:2px 0;font-size:13px;">{admin_email}</p>
            </div>
        </div>

        <div style="background:rgba(239,68,68,0.1);border-radius:10px;padding:15px;margin-top:30px;">
            <p style="color:#ef4444;margin:0;font-size:13px;"><strong>🛡️ Conseil de sécurité :</strong></p>
            <p style="color:#94a3b8;margin:5px 0;font-size:12px;">Si vous ne reconnaissez pas cette action ou si vous souhaitez contester ce motif, veuillez contacter immédiatement notre ligne d'urgence au <strong>+216 93162473</strong> ou répondre à cet e-mail.</p>
        </div>

        <p style="color:#475569;font-size:11px;text-align:center;margin-top:40px;border-top:1px solid #334155;padding-top:20px;">
          API Bank © 2026 - Sécurisé par Standard de Chiffrement Avancé (AES-256)
        </p>
      </div>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, app_password)
            server.sendmail(sender, target_email, msg.as_string())
        print(f"✅ Email de sécurité enrichi envoyé à {target_email}")
    except Exception as e:
        print(f"⚠️ Erreur SMTP Security Notification: {e}")

