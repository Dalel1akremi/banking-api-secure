from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from app.security.auth import verify_token
from app.db import accounts_collection, client, transactions_collection, users_collection
from app.rate_limiter import limiter
from werkzeug.security import generate_password_hash, check_password_hash
from app.routes.user import verify_auth_otp
import random
from datetime import datetime
import smtplib, os, io, bson
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from app.security.logger import log_activity
from dateutil.relativedelta import relativedelta
from fpdf import FPDF

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
    is_foreign: bool = False
    is_contactless: bool = False

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
    is_online: bool = False
    is_foreign: bool = False
    is_contactless: bool = False

class CardLimitsUpdate(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    online_payment_limit: float = Field(..., ge=0)
    atm_withdrawal_limit: float = Field(..., ge=0)
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class CardOptionsUpdate(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    contactless_payment: bool
    internet_payments: bool
    foreign_transactions: bool
    domestic_withdrawals: bool
    foreign_withdrawals: bool
    pin: str = Field(..., pattern=r"^\d{4}$")
    otp_code: str

class CardSubscriptionUpdate(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    subscription: str
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

class BillPayment(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    provider: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., pattern=r"^(electricity|water|internet|phone|gas|other)$")
    bill_reference: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9\-\/]+$")
    amount: float = Field(..., gt=0, le=1000000)
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
        "card_status":   "active",
        "card_subscription": "Standard",
        "online_payment_limit": 1000.0,
        "atm_withdrawal_limit": 500.0,
        "contactless_payment": True,
        "internet_payments": True,
        "foreign_transactions": False,
        "domestic_withdrawals": True,
        "foreign_withdrawals": False
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

    # ✅ Vérification des options et plafonds de la carte
    if data.is_contactless and not acc.get("contactless_payment", True):
        raise HTTPException(status_code=403, detail="Le paiement sans contact est désactivé pour cette carte.")
        
    if data.is_foreign and not acc.get("foreign_withdrawals", False):
        raise HTTPException(status_code=403, detail="Les retraits à l'étranger sont désactivés.")
        
    if not data.is_foreign and not acc.get("domestic_withdrawals", True):
        raise HTTPException(status_code=403, detail="Les retraits en Tunisie sont désactivés.")

    atm_limit = acc.get("atm_withdrawal_limit", 500.0)
    if data.amount > atm_limit:
        raise HTTPException(status_code=400, detail=f"Montant supérieur à votre plafond de retrait ({atm_limit} DT).")

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

    # ✅ Vérification des options et plafonds de la carte
    if data.is_contactless and not acc.get("contactless_payment", True):
        raise HTTPException(status_code=403, detail="Le paiement sans contact est désactivé pour cette carte.")
        
    if data.is_foreign and not acc.get("foreign_transactions", False):
        raise HTTPException(status_code=403, detail="Les transactions à l'étranger sont désactivées.")
        
    if data.is_online:
        if not acc.get("internet_payments", True):
            raise HTTPException(status_code=403, detail="Les paiements sur Internet sont désactivés.")
        online_limit = acc.get("online_payment_limit", 1000.0)
        if data.amount > online_limit:
            raise HTTPException(status_code=400, detail=f"Montant supérieur à votre plafond de paiement en ligne ({online_limit} DT).")

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
    RENEWAL_FEE = 0.0 if acc.get("card_subscription") == "Prime" else 10.0
    
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

# ==============================
# ⚙️ CARD SETTINGS
# ==============================

@router.post("/update-limits")
@limiter.limit("5/minute")
def update_limits(request: Request, data: CardLimitsUpdate, user=Depends(verify_token)):
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    verify_auth_otp(user["sub"], data.otp_code)
    
    # 💎 Restriction Prime : Seuls les membres Prime peuvent modifier les plafonds
    if acc.get("card_subscription") != "Prime":
        log_activity(str(user["id"]), data.account_number, "CARD_LIMITS_UPDATE", "FAILURE", {"reason": "Non-Prime access restriction"})
        raise HTTPException(status_code=403, detail="La modification des plafonds est réservée aux membres Prime.")

    accounts_collection.update_one(
        {"account_number": data.account_number},
        {"$set": {
            "online_payment_limit": data.online_payment_limit,
            "atm_withdrawal_limit": data.atm_withdrawal_limit
        }}
    )
    log_activity(str(user["id"]), data.account_number, "CARD_LIMITS_UPDATE", "SUCCESS", {"message": "Plafonds mis à jour"})
    return {"message": "Plafonds mis à jour avec succès."}

@router.post("/update-options")
@limiter.limit("5/minute")
def update_options(request: Request, data: CardOptionsUpdate, user=Depends(verify_token)):
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    verify_auth_otp(user["sub"], data.otp_code)

    accounts_collection.update_one(
        {"account_number": data.account_number},
        {"$set": {
            "contactless_payment": data.contactless_payment,
            "internet_payments": data.internet_payments,
            "foreign_transactions": data.foreign_transactions,
            "domestic_withdrawals": data.domestic_withdrawals,
            "foreign_withdrawals": data.foreign_withdrawals
        }}
    )
    log_activity(str(user["id"]), data.account_number, "CARD_OPTIONS_UPDATE", "SUCCESS", {"message": "Options mises à jour"})
    return {"message": "Options de la carte mises à jour."}

@router.post("/update-subscription")
@limiter.limit("2/minute")
def update_subscription(request: Request, data: CardSubscriptionUpdate, user=Depends(verify_token)):
    acc = verify_pin(data.account_number, str(user["id"]), data.pin)
    verify_auth_otp(user["sub"], data.otp_code)

    if acc.get("card_subscription") == data.subscription:
        raise HTTPException(status_code=400, detail=f"Vous êtes déjà abonné à {data.subscription}.")
    
    fee = 20.0 if data.subscription == "Prime" else 0.0

    if fee > 0 and acc["balance"] < fee:
        raise HTTPException(status_code=400, detail=f"Solde insuffisant pour souscrire à {data.subscription} (frais de {fee} DT).")

    update_fields = {"$set": {"card_subscription": data.subscription}}
    if fee > 0:
        update_fields["$inc"] = {"balance": -fee}

    accounts_collection.update_one({"account_number": data.account_number}, update_fields)
    
    if fee > 0:
        save_transaction({
            "type": "service_fee",
            "description": f"Frais abonnement {data.subscription}",
            "account_number": data.account_number,
            "amount": fee,
            "owner_id": str(user["id"])
        })

    log_activity(str(user["id"]), data.account_number, "CARD_SUBSCRIPTION_UPDATE", "SUCCESS", {"subscription": data.subscription})
    return {"message": f"Abonnement mis à jour vers {data.subscription}."}


# ==============================
# 📄 RIB / IBAN
# ==============================

def generate_rib_key(bank_code: str, branch_code: str, account_number: str) -> str:
    """Calcule la clé RIB tunisienne (modulo 97)."""
    num_str = bank_code + branch_code + account_number + "00"
    # Convert letters to digits (A=1, B=2, ...)
    numeric = "".join(
        str(ord(c) - 64) if c.isalpha() else c for c in num_str
    )
    key = 97 - (int(numeric) % 97)
    return str(key).zfill(2)

@router.get("/{account_number}/rib")
def get_rib(account_number: str, user=Depends(verify_token)):
    acc = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": str(user["id"])
    })
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable")

    # RIB Tunisien simulé : banque=03, agence=001, numéro=account_number padded to 13
    bank_code   = "03"
    branch_code = "001"
    acc_padded  = account_number.zfill(13)
    rib_key     = generate_rib_key(bank_code, branch_code, acc_padded)
    rib         = f"{bank_code} {branch_code} {acc_padded} {rib_key}"

    # IBAN Tunisien : TN59 + bank(2) + branch(3) + account(13) + key(2)
    iban_raw = f"TN59{bank_code}{branch_code}{acc_padded}{rib_key}"
    iban     = " ".join(iban_raw[i:i+4] for i in range(0, len(iban_raw), 4))

    db_user = users_collection.find_one({"_id": bson.ObjectId(user["id"])})
    owner_name = f"{db_user.get('username','')} {db_user.get('lastname','')}".strip() if db_user else "Titulaire"

    return {
        "account_number": account_number,
        "rib": rib,
        "iban": iban,
        "bank_name": "API Bank",
        "bank_code": bank_code,
        "branch_code": branch_code,
        "owner_name": owner_name,
    }

@router.get("/{account_number}/rib/pdf")
def download_rib_pdf(account_number: str, user=Depends(verify_token)):
    acc = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": str(user["id"])
    })
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable")

    bank_code   = "03"
    branch_code = "001"
    acc_padded  = account_number.zfill(13)
    rib_key     = generate_rib_key(bank_code, branch_code, acc_padded)
    rib         = f"{bank_code} {branch_code} {acc_padded} {rib_key}"
    iban_raw    = f"TN59{bank_code}{branch_code}{acc_padded}{rib_key}"
    iban        = " ".join(iban_raw[i:i+4] for i in range(0, len(iban_raw), 4))

    db_user = users_collection.find_one({"_id": bson.ObjectId(user["id"])})
    owner_name = f"{db_user.get('username','')} {db_user.get('lastname','')}".strip() if db_user else "Titulaire"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_margins(20, 20, 20)

    # Header
    pdf.set_fill_color(30, 41, 59)
    pdf.rect(0, 0, 210, 45, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(20, 12)
    pdf.cell(0, 10, "API Bank", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_xy(20, 25)
    pdf.cell(0, 8, "Relevé d'Identité Bancaire (RIB)", ln=True)

    pdf.set_text_color(30, 41, 59)
    pdf.set_xy(20, 55)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Informations du titulaire", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_xy(20, 65)
    pdf.cell(60, 8, "Titulaire :", ln=False)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, owner_name, ln=True)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_xy(20, 75)
    pdf.cell(60, 8, "Date d'émission :", ln=False)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, datetime.utcnow().strftime("%d/%m/%Y"), ln=True)

    # RIB Box
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(15, 90, 180, 55, 'F')
    pdf.set_draw_color(99, 102, 241)
    pdf.rect(15, 90, 180, 55, 'D')

    pdf.set_text_color(30, 41, 59)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_xy(20, 95)
    pdf.cell(0, 8, "Coordonnées bancaires", ln=True)

    rows = [
        ("Banque", f"{bank_code} — API Bank"),
        ("Agence", branch_code),
        ("Numéro de compte", account_number),
        ("Clé RIB", rib_key),
        ("RIB complet", rib),
        ("IBAN", iban),
    ]
    y = 106
    for label, value in rows:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.set_xy(22, y)
        pdf.cell(55, 7, label + " :", ln=False)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 7, value, ln=True)
        y += 7

    # Footer
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(0, 260, 210, 37, 'F')
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(148, 163, 184)
    pdf.set_xy(20, 265)
    pdf.multi_cell(170, 5, "Ce document est généré automatiquement par API Bank. Il est valable comme justificatif d'identité bancaire. Document confidentiel — ne pas divulguer à des tiers non autorisés.", align="C")

    buf = io.BytesIO(pdf.output())
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="RIB_{account_number}.pdf"'}
    )


# ==============================
# 📜 TRANSACTION RECEIPT PDF
# ==============================

@router.get("/receipt/{account_number}/{tx_index}")
def download_receipt(account_number: str, tx_index: int, user=Depends(verify_token)):
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # Verify account ownership
    acc = accounts_collection.find_one({
        "account_number": account_number,
        "owner_id": str(db_user["_id"])
    })
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable ou accès non autorisé")

    # Get transactions EXACTLY like the frontend shows them
    transactions = list(transactions_collection.find(
        {
            "$or": [
                {"account_number": account_number},
                {"from_account": account_number},
                {"to_account": account_number}
            ]
        }
    ).sort("timestamp", -1))

    if tx_index < 0 or tx_index >= len(transactions):
        print(f"DEBUG: tx_index {tx_index} out of range for {len(transactions)} txs")
        raise HTTPException(status_code=404, detail="Transaction introuvable (Index hors limites)")

    tx = transactions[tx_index]

    # Determine direction & data
    tx_type = tx.get("type", "unknown")
    amount  = tx.get("amount", 0.0)
    ts      = tx.get("timestamp")
    ts_str  = ts.strftime("%d/%m/%Y %H:%M:%S") if hasattr(ts, "strftime") else str(ts)[:19]
    owner_name = f"{db_user.get('username','')} {db_user.get('lastname','')}".strip().upper() or "CLIENT API BANK"

    # --- Thème dynamique ---
    themes = {
        "transfer": ("VIREMENT BANCAIRE", (99, 102, 241)),  # Indigo
        "bill_payment": ("PAIEMENT DE FACTURE", (139, 92, 246)), # Violet
        "deposit": ("DÉPÔT EN ESPÈCES", (34, 197, 94)), # Green
        "withdraw": ("RETRAIT D'ARGENT", (239, 68, 68)), # Red
        "payment": ("PAIEMENT COMMERÇANT", (20, 184, 166)), # Teal
    }
    title_label, primary_color = themes.get(tx_type, ("TRANSACTION BANCAIRE", (71, 85, 105)))
    ref = str(tx.get("_id", ""))[-10:].upper()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_fill_color(252, 252, 253)
    pdf.rect(0, 0, 210, 297, 'F')
    
    pdf.set_fill_color(*primary_color)
    pdf.rect(0, 0, 210, 50, 'F')
    
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_xy(20, 15)
    pdf.cell(0, 10, "API Bank", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_xy(20, 28)
    pdf.cell(0, 5, "La banque digitale de demain, sécurisée aujourd'hui.", ln=True)
    
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_xy(20, 65)
    pdf.set_text_color(*primary_color)
    pdf.cell(0, 10, title_label, ln=True)
    pdf.set_draw_color(*primary_color)
    pdf.line(20, 75, 190, 75)

    pdf.set_fill_color(255, 255, 255)
    pdf.set_draw_color(226, 232, 240)
    pdf.rect(20, 85, 170, 45, 'FD')
    pdf.set_xy(20, 95)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(170, 10, "Montant de l'opération", align="C", ln=True)
    pdf.set_font("Helvetica", "B", 34)
    pdf.set_text_color(30, 41, 59)
    direction = "+" if tx_type == "deposit" or (tx_type == "transfer" and tx.get("to_account") == account_number) else "-"
    pdf.cell(170, 15, f"{direction} {amount:,.2f} TND", align="C", ln=True)

    pdf.set_xy(20, 145)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 10, "INFORMATIONS DÉTAILLÉES", ln=True)
    
    details = [
        ("Référence Transaction", f"TXN-{ref}"),
        ("Date de valeur", ts_str[:10]),
        ("Heure de l'opération", ts_str[11:19] + " UTC"),
        ("Titulaire du compte", owner_name.upper()),
        ("Compte débité", f"TN59 12345 {account_number} 45"),
    ]

    if tx_type == "transfer":
        details.append(("Bénéficiaire", tx.get("to_account", "N/A")))
        details.append(("Motif / Label", tx.get("description", "Virement sortant")))
    elif tx_type == "bill_payment":
        details.append(("Prestataire", tx.get("provider", "N/A").upper()))
        details.append(("Référence Facture", tx.get("bill_reference", "N/A")))
    elif tx_type == "payment":
        details.append(("Marchand", tx.get("merchant", "N/A")))
    
    details.append(("Statut", "CONFIRMÉ / EXÉCUTÉ"))

    y = 158
    for i, (label, value) in enumerate(details):
        if i % 2 == 0:
            pdf.set_fill_color(248, 250, 252)
            pdf.rect(20, y, 170, 12, 'F')
        pdf.set_xy(25, y + 3)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(60, 6, label)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(100, 6, str(value), align="R", ln=True)
        y += 12

    pdf.set_xy(140, y + 20)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*primary_color)
    pdf.cell(50, 5, "SÉCURISÉ PAR API BANK", align="C", ln=True)
    pdf.rect(140, y + 18, 50, 15)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_xy(140, y + 24)
    pdf.cell(50, 5, "Signature Numérique : Validée", align="C", ln=True)

    pdf.set_xy(20, 265)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(20, 264, 190, 264)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(148, 163, 184)
    footer_text = "Ce document est un justificatif officiel généré par le système API Bank. API Bank S.A. au capital de 100.000.000 TND — 1002 Tunis, Tunisie."
    pdf.multi_cell(170, 4, footer_text, align="C")

    buf = io.BytesIO(pdf.output())
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="Recu_API_Bank_{ref}.pdf"'})


# ==============================
# 💡 BILL PAYMENT
# ==============================

@router.post("/bill-payment")
@limiter.limit("10/minute")
def bill_payment(request: Request, data: BillPayment, user=Depends(verify_token)):
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Le montant doit être positif")

    acc = verify_pin(data.account_number, str(user["id"]), data.pin)

    if acc.get("card_status") == "deactivated":
        raise HTTPException(status_code=403, detail="Cette carte est désactivée.")
    if is_card_expired(acc.get("card_expiry", "01/01")):
        raise HTTPException(status_code=403, detail="Cette carte est expirée.")
    if not acc.get("internet_payments", True):
        raise HTTPException(status_code=403, detail="Les paiements en ligne sont désactivés.")

    online_limit = acc.get("online_payment_limit", 1000.0)
    if data.amount > online_limit:
        raise HTTPException(status_code=400, detail=f"Montant supérieur au plafond en ligne ({online_limit} DT).")

    verify_auth_otp(user["sub"], data.otp_code)

    if acc["balance"] < data.amount:
        raise HTTPException(status_code=400, detail="Solde insuffisant")

    result = accounts_collection.update_one(
        {"account_number": data.account_number, "owner_id": str(user["id"]), "balance": {"$gte": data.amount}},
        {"$inc": {"balance": -data.amount}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="Solde insuffisant ou compte introuvable")

    save_transaction({
        "type": "bill_payment",
        "account_number": data.account_number,
        "merchant": data.provider,
        "provider": data.provider,
        "category": data.category,
        "bill_reference": data.bill_reference,
        "amount": data.amount,
        "owner_id": str(user["id"])
    })
    log_activity(str(user["id"]), data.account_number, "BILL_PAYMENT", "SUCCESS", {
        "amount": data.amount, "provider": data.provider, "category": data.category
    })
    return {"message": f"Facture {data.provider} payée avec succès."}