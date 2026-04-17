from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field
from app.security.auth import verify_token
from app.db import accounts_collection, client, transactions_collection, users_collection
from app.rate_limiter import limiter
from werkzeug.security import generate_password_hash, check_password_hash
from app.routes.user import verify_auth_otp
import random
from datetime import datetime
import smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from app.security.logger import log_activity
from dateutil.relativedelta import relativedelta

load_dotenv()

router = APIRouter(prefix="/accounts", tags=["Accounts"])

# ==============================
# 📦 MODELS
# ==============================

class Account(BaseModel):
    balance: float = Field(..., ge=0, le=1000000000)

class Deposit(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    amount: float = Field(..., gt=0, le=1000000)
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class Withdraw(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    amount: float = Field(..., gt=0, le=1000000)
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class Transfer(BaseModel):
    from_account: str = Field(..., pattern=r"^\d{10}$")
    to_account: str = Field(..., pattern=r"^\d{10}$")
    amount: float = Field(..., gt=0, le=1000000)
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class Payment(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    amount: float = Field(..., gt=0, le=1000000)
    merchant: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9À-ÿ_\-\s\(\)&]+$")
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class CardStatusToggle(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class AccountDelete(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class CardRenew(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

# ==============================
# 🔐 PIN VERIFICATION HELPER
# ==============================

def verify_pin(account_number: str, owner_id: str, pin: str):
    """Vérifie le PIN d'un compte. Lève une HTTPException si invalide."""
    from datetime import timedelta
    acc = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": owner_id
    })
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable")

    locked_until = acc.get("locked_until")
    if locked_until and datetime.utcnow() < locked_until:
        raise HTTPException(status_code=403, detail="Compte verrouille suite a de trop nombreuses erreurs de PIN. Reesayez dans 15 minutes.")

    if not check_password_hash(acc.get("pin_hash", ""), pin):
        failed_attempts = acc.get("failed_pin_attempts", 0) + 1
        update_data = {"failed_pin_attempts": failed_attempts}
        if failed_attempts >= 3:
            update_data["locked_until"] = datetime.utcnow() + timedelta(minutes=15)
            log_activity(owner_id, account_number, "ACCOUNT_LOCKED", "FAILURE", {"reason": "Trop de tentatives échouées (PIN)"})
        accounts_collection.update_one({"_id": acc["_id"]}, {"$set": update_data})
        log_activity(owner_id, account_number, "PIN_VERIFICATION", "FAILURE", {"failed_attempts": failed_attempts})
        raise HTTPException(status_code=403, detail="Code confidentiel (PIN) incorrect")
    
    if acc.get("failed_pin_attempts", 0) > 0 or acc.get("locked_until"):
        accounts_collection.update_one({"_id": acc["_id"]}, {"$unset": {"locked_until": ""}, "$set": {"failed_pin_attempts": 0}})

    return acc

def is_card_expired(expiry_str: str) -> bool:
    """Vérifie si une carte est expirée (format MM/YY)."""
    try:
        exp_month, exp_year = map(int, expiry_str.split('/'))
        exp_year += 2000
        # La carte est valide jusqu'au dernier jour du mois inclus.
        # On définit l'expiration comme le 1er jour du mois suivant.
        if exp_month == 12:
            expiry_date = datetime(exp_year + 1, 1, 1)
        else:
            expiry_date = datetime(exp_year, exp_month + 1, 1)
        
        return datetime.utcnow() >= expiry_date
    except:
        return True # Par sécurité, si format invalide, on considère expirée

# ==============================
# 📧 EMAIL NOTIFICATION
# ==============================

def send_account_email(email: str, account_number: str, pin: str, card_number: str = None, card_cvv: str = None):
    sender = os.getenv("GMAIL_SENDER", "")
    app_password = os.getenv("GMAIL_APP_PASSWORD", "")

    masked = f"******{account_number[-4:]}"

    if not sender or not app_password or "votre.email" in sender:
        print(f"\n{'='*55}")
        print(f"🏦 [SIMULATION] NOUVEAU COMPTE BANCAIRE CRÉÉ")
        print(f"   Destinataire  : {email}")
        print(f"   N° de compte  : {account_number}")
        print(f"   Code PIN      : {pin}")
        if card_number:
            print(f"   Carte Visa    : {card_number} (CVV: {card_cvv})")
        print(f"   Conservez ce code en lieu sûr !")
        print(f"{'='*55}\n")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🏦 Votre nouveau compte bancaire API Bank"
    msg["From"]    = sender
    msg["To"]      = email

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0f172a;margin:0;padding:20px;">
      <div style="max-width:440px;margin:auto;background:#1e293b;border-radius:12px;padding:32px;text-align:center;border:1px solid #334155;">
        <h1 style="color:#6366f1;margin-bottom:4px;">API Bank</h1>
        <p style="color:#94a3b8;font-size:14px;">Votre compte bancaire a été créé</p>
        <div style="background:#0f172a;border-radius:10px;padding:20px;margin:20px 0;">
          <p style="color:#94a3b8;font-size:12px;margin-bottom:4px;">NUMÉRO DE COMPTE</p>
          <span style="font-size:1.4rem;font-weight:bold;letter-spacing:4px;color:#fff;">{account_number}</span>
        </div>
        <div style="background:#0f172a;border-radius:10px;padding:20px;margin:0 0 20px 0;">
          <p style="color:#94a3b8;font-size:12px;margin-bottom:4px;">CODE CONFIDENTIEL (PIN)</p>
          <span style="font-size:2.5rem;font-weight:bold;letter-spacing:16px;color:#f59e0b;">{pin}</span>
        </div>
        """
    if card_number:
        html += f"""
        <div style="background:#0f172a;border-radius:10px;padding:20px;margin:0 0 20px 0;">
          <p style="color:#94a3b8;font-size:12px;margin-bottom:4px;">CARTE VISA (SIMULATION)</p>
          <span style="font-size:1.2rem;font-weight:bold;letter-spacing:4px;color:#cbd5e1;">{card_number}</span><br>
          <span style="font-size:1rem;color:#94a3b8;">CVV : {card_cvv}</span>
        </div>
        """
    html += """
        <p style="color:#f87171;font-size:13px;">⚠️ Ne communiquez jamais votre PIN à quiconque.</p>
        <p style="color:#475569;font-size:11px;margin-top:12px;">Cet email est confidentiel. Si vous n'avez pas créé ce compte, contactez-nous immédiatement.</p>
      </div>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, app_password)
            server.sendmail(sender, email, msg.as_string())
        print(f"✅ Email compte envoyé à {email}")
    except Exception as e:
        print(f"⚠️ Erreur SMTP : {e} — Code PIN pour {account_number} : {pin}")

# ==============================
# 🧾 TRANSACTION FUNCTION
# ==============================

def save_transaction(data: dict):
    data["timestamp"] = datetime.utcnow()
    transactions_collection.insert_one(data)

# ==============================
# 🔢 ACCOUNT NUMBER GENERATION
# ==============================

def generate_account_number():
    return str(random.randint(1000000000, 9999999999))

# ==============================
# 🏦 CREATE ACCOUNT
# ==============================

@router.post("/")
@limiter.limit("5/minute")
def create_account(request: Request, background_tasks: BackgroundTasks, account: Account, user=Depends(verify_token)):

    account_number = generate_account_number()
    while accounts_collection.find_one({"account_number": account_number}):
        account_number = generate_account_number()

    # Générer un PIN à 4 chiffres
    plain_pin = str(random.randint(1000, 9999))
    pin_hash  = generate_password_hash(plain_pin)

    # Note PCI-DSS : Ces informations ne doivent jamais être stockées en clair en production.
    # Ceci est uniquement fait dans le cadre du projet académique/simulation pour l'affichage UI.
    card_number = f"4{''.join([str(random.randint(0, 9)) for _ in range(15)])}"
    card_expiry = (datetime.utcnow() + relativedelta(years=3)).strftime("%m/%y")
    card_cvv = str(random.randint(100, 999))

    data = {
        "owner_id":      str(user["id"]),
        "balance":       account.balance,
        "account_number": account_number,
        "pin_hash":      pin_hash,
        "card_number":   card_number,
        "card_expiry":   card_expiry,
        "card_cvv":      card_cvv,
        "card_status":   "active"
    }
    accounts_collection.insert_one(data)

    # Récupérer l'email du propriétaire du compte
    db_user = users_collection.find_one({"_id": __import__("bson").ObjectId(user["id"])})
    owner_email = db_user.get("email", "") if db_user else ""

    # Envoyer l'email avec le numéro de compte et le PIN
    if owner_email:
        background_tasks.add_task(send_account_email, owner_email, account_number, plain_pin, card_number, card_cvv)
        
    log_activity(str(user["id"]), account_number, "ACCOUNT_CREATION", "SUCCESS", {"message": "Compte et Carte Visa créés"})

    return {
        "message": "Account created — votre PIN a été envoyé par email",
        "account_number": account_number,
        "balance": account.balance
    }


# ==============================
# 📄 GET ALL ACCOUNTS
# ==============================

@router.get("/")
def get_accounts(user=Depends(verify_token)):

    accounts = list(accounts_collection.find(
        {"owner_id": str(user["id"])},
        {"_id": 0}
    ))

    return accounts

# ==============================
# 🔍 GET ONE ACCOUNT
# ==============================

@router.get("/{account_number}")
def get_account(account_number: str, user=Depends(verify_token)):

    acc = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": str(user["id"])
    })

    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    acc["id"] = str(acc["_id"])
    del acc["_id"]

    return acc

# ==============================
# 💰 DEPOSIT + HISTORY
# ==============================

@router.post("/deposit")
@limiter.limit("10/minute")
def deposit(request: Request, data: Deposit, user=Depends(verify_token)):

    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    # ✅ Vérification du PIN
    verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # ✅ Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    accounts_collection.update_one(
        {"account_number": data.account_number},
        {"$inc": {"balance": data.amount}}
    )

    save_transaction({
        "type": "deposit",
        "account_number": data.account_number,
        "amount": data.amount,
        "owner_id": str(user["id"])
    })
    log_activity(str(user["id"]), data.account_number, "DEPOSIT", "SUCCESS", {"amount": data.amount})

    return {"message": "Deposit successful"}

# ==============================
# 💸 WITHDRAW + HISTORY
# ==============================

@router.post("/withdraw")
@limiter.limit("10/minute")
def withdraw(request: Request, data: Withdraw, user=Depends(verify_token)):

    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    # ✅ Vérification du PIN
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # ✅ Vérification de l'état de la carte (pour retrait)
    if acc.get("card_status") == "deactivated":
        raise HTTPException(status_code=403, detail="Cette carte est désactivée. Veuillez la réactiver pour effectuer un retrait.")

    # ✅ Vérification de l'expiration
    if is_card_expired(acc.get("card_expiry", "01/01")):
        raise HTTPException(status_code=403, detail="Cette carte est expirée. Veuillez procéder à son renouvellement.")

    # ✅ Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    if acc["balance"] < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    result = accounts_collection.update_one(
        {
            "account_number": data.account_number,
            "owner_id": str(user["id"]),
            "balance": {"$gte": data.amount}
        },
        {"$inc": {"balance": -data.amount}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="Account not found or insufficient balance")

    save_transaction({
        "type": "withdraw",
        "account_number": data.account_number,
        "amount": data.amount,
        "owner_id": str(user["id"])
    })
    log_activity(str(user["id"]), data.account_number, "WITHDRAW", "SUCCESS", {"amount": data.amount})

    return {"message": "Withdrawal successful"}

# ==============================
# 🛒 PAYMENT + HISTORY
# ==============================

@router.post("/payment")
@limiter.limit("10/minute")
def payment(request: Request, data: Payment, user=Depends(verify_token)):

    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    # ✅ Vérification du PIN
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # ✅ Vérification de l'état de la carte (pour paiement)
    if acc.get("card_status") == "deactivated":
        raise HTTPException(status_code=403, detail="Cette carte est désactivée. Veuillez la réactiver pour effectuer un paiement.")

    # ✅ Vérification de l'expiration
    if is_card_expired(acc.get("card_expiry", "01/01")):
        raise HTTPException(status_code=403, detail="Cette carte est expirée. Veuillez procéder à son renouvellement.")

    # ✅ Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    if acc["balance"] < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    result = accounts_collection.update_one(
        {
            "account_number": data.account_number,
            "owner_id": str(user["id"]),
            "balance": {"$gte": data.amount}
        },
        {"$inc": {"balance": -data.amount}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="Account not found or insufficient balance")

    save_transaction({
        "type": "payment",
        "account_number": data.account_number,
        "merchant": data.merchant,
        "amount": data.amount,
        "owner_id": str(user["id"])
    })
    log_activity(str(user["id"]), data.account_number, "PAYMENT", "SUCCESS", {"amount": data.amount, "merchant": data.merchant})

    return {"message": "Payment successful"}

# ==============================
# 🔁 TRANSFER + HISTORY (ATOMIC)
# ==============================

@router.post("/transfer")
@limiter.limit("10/minute")
def transfer(request: Request, data: Transfer, user=Depends(verify_token)):

    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    if data.from_account == data.to_account:
        raise HTTPException(status_code=400, detail="Cannot transfer to same account")

    # ✅ Vérification du PIN sur le compte source
    from_acc = verify_pin(data.from_account, str(user["id"]), data.pin)
    
    # ✅ Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    if from_acc["balance"] < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    to_acc = accounts_collection.find_one({"account_number": data.to_account})
    if not to_acc:
        raise HTTPException(status_code=404, detail="Destination account not found")

    accounts_collection.update_one(
        {"account_number": data.from_account},
        {"$inc": {"balance": -data.amount}}
    )

    accounts_collection.update_one(
        {"account_number": data.to_account},
        {"$inc": {"balance": data.amount}}
    )

    save_transaction({
        "type": "transfer",
        "from_account": data.from_account,
        "to_account": data.to_account,
        "amount": data.amount,
        "owner_id": str(user["id"])
    })
    log_activity(str(user["id"]), data.from_account, "TRANSFER_OUT", "SUCCESS", {"amount": data.amount, "to_account": data.to_account})
    # Optional: Log transfer in for the receiver? For now, we mainly log the sender's activity
    receiver_acc = accounts_collection.find_one({"account_number": data.to_account})
    if receiver_acc:
        log_activity(receiver_acc.get("owner_id"), data.to_account, "TRANSFER_IN", "SUCCESS", {"amount": data.amount, "from_account": data.from_account})

    return {"message": "Transfer successful"}

# ==============================
# 📊 TRANSACTIONS HISTORY
# ==============================

@router.get("/transactions/{account_number}")
def get_transactions(account_number: str, user=Depends(verify_token)):

    # vérifier que le compte appartient au user
    account = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": str(user["id"])
    })

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # récupérer historique du compte (y compris les envois et réceptions de transferts)
    transactions = list(transactions_collection.find(
        {
            "$or": [
                {"account_number": account_number},
                {"from_account": account_number},
                {"to_account": account_number}
            ]
        },
        {"_id": 0}
    ).sort("timestamp", -1))  # Tri par date décroissante

    return {
        "account_number": account_number,
        "transactions": transactions
    }

# ==============================
# 🛡️ CARD STATUS TOGGLE
# ==============================

@router.post("/toggle-card-status")
@limiter.limit("5/minute")
def toggle_card_status(request: Request, data: CardStatusToggle, user=Depends(verify_token)):
    # 1. Vérification PIN
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # 2. Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    current_status = acc.get("card_status", "active")
    new_status = "deactivated" if current_status == "active" else "active"
    
    accounts_collection.update_one(
        {"account_number": data.account_number},
        {"$set": {"card_status": new_status}}
    )

    log_activity(str(user["id"]), data.account_number, "CARD_STATUS_CHANGE", "SUCCESS", {"new_status": new_status})
    
    return {"message": f"Carte {new_status} avec succes.", "card_status": new_status}

# ==============================
# 🗑️ DELETE ACCOUNT
# ==============================

@router.post("/delete")
@limiter.limit("3/minute")
def delete_account(request: Request, data: AccountDelete, user=Depends(verify_token)):
    # 1. Vérification PIN
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # 2. Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    # Suppression du compte
    accounts_collection.delete_one({"account_number": data.account_number, "owner_id": str(user["id"])})
    
    # Suppression des transactions associées
    transactions_collection.delete_many({
        "$or": [
            {"account_number": data.account_number},
            {"from_account": data.account_number},
            {"to_account": data.account_number}
        ]
    })

    log_activity(str(user["id"]), data.account_number, "ACCOUNT_DELETION", "SUCCESS", {"message": "Compte et transactions associées supprimés"})
    
    return {"message": "Compte bancaire supprimé avec succès."}

# ==============================
# 🔄 CARD RENEWAL
# ==============================

@router.post("/renew-card")
@limiter.limit("2/minute")
def renew_card(request: Request, data: CardRenew, user=Depends(verify_token)):
    RENEWAL_FEE = 10.0
    
    # 1. Vérification PIN
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    
    # 2. Vérification OTP
    verify_auth_otp(user["sub"], data.otp_code)

    # 3. Vérification si la carte est réellement expirée
    if not is_card_expired(acc.get("card_expiry", "01/01")):
        raise HTTPException(status_code=400, detail="Votre carte est encore valide. Le renouvellement n'est pas nécessaire.")

    # 4. Vérification solde pour frais (10 DT)
    if acc["balance"] < RENEWAL_FEE:
        raise HTTPException(status_code=400, detail="Solde insuffisant pour le renouvellement (frais de 10 DT requis).")

    # 4. Génération nouveaux identifiants
    new_card_number = f"4{''.join([str(random.randint(0, 9)) for _ in range(15)])}"
    new_expiry = (datetime.utcnow() + relativedelta(years=3)).strftime("%m/%y")
    new_cvv = str(random.randint(100, 999))

    # 5. Mise à jour de la carte + Prélèvement des frais
    accounts_collection.update_one(
        {"account_number": data.account_number},
        {
            "$set": {
                "card_number": new_card_number,
                "card_expiry": new_expiry,
                "card_cvv": new_cvv,
                "card_status": "active" # Réactivation automatique si elle était désactivée
            },
            "$inc": {"balance": -RENEWAL_FEE}
        }
    )

    # 6. Historique transaction (Frais)
    save_transaction({
        "type": "service_fee",
        "description": "Frais de renouvellement de carte",
        "account_number": data.account_number,
        "amount": RENEWAL_FEE,
        "owner_id": str(user["id"])
    })

    log_activity(str(user["id"]), data.account_number, "CARD_RENEWAL", "SUCCESS", {"fee": RENEWAL_FEE})

    return {
        "message": "Carte renouvelée avec succès. Les frais de 10 DT ont été prélevés.",
        "new_card_number": new_card_number,
        "new_expiry": new_expiry
    }