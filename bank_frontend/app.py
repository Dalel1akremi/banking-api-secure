from flask import Flask, render_template, request, redirect, session, flash, Response, send_file, url_for
import requests
from fpdf import FPDF
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = "secretkey"

@app.template_filter('tx_type_fr')
def translate_tx_type(tx_type):
    return {
        'deposit': 'Depot',
        'withdraw': 'Retrait',
        'transfer': 'Virement',
        'payment': 'Paiement',
        'bill_payment': 'Facture',
        'phone_recharge': 'Recharge',
        'service_fee': 'Frais',
        'checkbook_request': 'Chequier'
    }.get(tx_type, str(tx_type).replace('_', ' ').title())

@app.template_filter('status_fr')
def translate_status(status):
    mapping = {
        'SUCCESS': 'Succes',
        'FAILED': 'Echec',
        'PENDING': 'En attente',
        'UNREAD': 'Non lu',
        'READ': 'Lu',
        'RESOLVED': 'Resolu',
        'LOCKED': 'Verrouille',
        'ACTIVE': 'Actif'
    }
    return mapping.get(str(status).upper(), str(status).title())

@app.template_filter('action_fr')
def translate_action(action):
    mapping = {
        'LOGIN': 'Connexion',
        'LOGOUT': 'Deconnexion',
        'TRANSACTION': 'Transaction',
        'ACCOUNT_DELETION': 'Suppression de compte',
        'CARD_STATUS_CHANGE': 'Changement statut carte',
        'ACCOUNT_LOCKED': 'Verrouillage de compte',
        'TRANSFER': 'Virement',
        'DEPOSIT': 'Depot',
        'WITHDRAWAL': 'Retrait',
        'PAYMENT': 'Paiement',
        'BILL_PAYMENT': 'Paiement facture',
        'PHONE_RECHARGE': 'Recharge telephonique',
        'CHECKBOOK_REQUEST': 'Demande chequier'
    }
    return mapping.get(str(action).upper(), str(action).replace('_', ' ').title())

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

BASE_API_URL = "http://127.0.0.1:8000"

@app.context_processor
def inject_is_admin():
    import base64
    import json
    token = session.get("token")
    if not token: return dict(is_admin=False)
    try:
        payload = token.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.b64decode(payload).decode("utf-8")
        data = json.loads(decoded)
        return dict(is_admin=data.get("is_admin", False))
    except:
        return dict(is_admin=False)

def is_card_expired(expiry_str: str) -> bool:
    if not expiry_str: return True
    try:
        from datetime import datetime
        exp_month, exp_year = map(int, expiry_str.split('/'))
        exp_year += 2000
        now = datetime.utcnow()
        # Card is valid until the end of the month
        if exp_month == 12:
            expiry_date = datetime(exp_year + 1, 1, 1)
        else:
            expiry_date = datetime(exp_year, exp_month + 1, 1)
        return now >= expiry_date
    except:
        return True

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        response = requests.post(f"{BASE_API_URL}/auth/login", json={
            "email": email,
            "password": password
        })

        if response.status_code == 200:
            data = response.json()
            if data.get("require_otp"):
                return render_template("verify_login.html", email=email, message=data.get("message", ""))
            
            session["token"] = data.get("access_token")
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid credentials", email=email)

    return render_template("login.html", email="")

@app.route("/verify_login", methods=["POST"])
@limiter.limit("5 per minute")
def verify_login():
    email = request.form["email"]
    otp_code = request.form["otp_code"]
    
    response = requests.post(f"{BASE_API_URL}/auth/verify-2fa", json={
        "email": email,
        "otp_code": otp_code
    })
    
    if response.status_code == 200:
        data = response.json()
        session["token"] = data["access_token"]
        return redirect("/dashboard")
    else:
        try:
            detail = response.json().get("detail", "Code incorrect")
        except:
            detail = "Erreur de validation"
        return render_template("verify_login.html", email=email, error=detail)

@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")

@app.route("/request_otp", methods=["POST"])
@limiter.limit("3 per minute")
def request_otp():
    email = request.json.get("email", "")
    res = requests.post(f"{BASE_API_URL}/verification/request-otp", json={"email": email})
    return (res.content, res.status_code, {"Content-Type": "application/json"})

@app.route("/request_auth_otp", methods=["POST"])
@limiter.limit("5 per minute")
def request_auth_otp():
    if "token" not in session: return ("Unauthorized", 401)
    res = requests.post(f"{BASE_API_URL}/verification/request-auth-otp", headers=get_headers())
    return (res.content, res.status_code, {"Content-Type": "application/json"})

@app.route("/process_signup", methods=["POST"])
@limiter.limit("5 per minute")
def process_signup():
    username = request.form["username"]
    lastname = request.form["lastname"]
    cin = request.form["cin"]
    email = request.form["email"]
    password = request.form["password"]
    phone = request.form.get("phone", "").strip() or None
    verification_code = request.form["verification_code"]

    payload = {
        "username": username,
        "lastname": lastname,
        "cin": cin,
        "email": email,
        "password": password,
        "verification_code": verification_code
    }
    if phone:
        payload["phone"] = phone

    res = requests.post(f"{BASE_API_URL}/users/", json=payload)

    if res.status_code == 200:
        flash("Compte créé avec succès ! Vous pouvez vous connecter.", "success")
        return redirect("/")
    else:
        error_detail = res.json().get("detail", "Données invalides.")
        if isinstance(error_detail, list):
            error_msg = error_detail[0].get("msg", "Erreur de format")
            field = error_detail[0].get("loc", ["", ""])[-1]
            flash(f"Erreur sur le champ '{field}' : {error_msg}", "error")
        else:
            flash(error_detail, "error")
        return render_template("signup.html", username=username, lastname=lastname, cin=cin, email=email, phone=phone or "")

@app.route("/logout")
def logout():
    session.pop("token", None)
    return redirect("/")

def get_headers():
    return {"Authorization": f"Bearer {session.get('token')}"}

@app.route("/dashboard")
def dashboard():
    if "token" not in session:
        return redirect("/")
    
    response = requests.get(f"{BASE_API_URL}/accounts/", headers=get_headers())
    if response.status_code == 200:
        accounts = response.json()
    else:
        accounts = []
        if response.status_code == 401:
            return redirect("/logout")
    
    # Fetch activity logs for the global dashboard activity feed
    act_res = requests.get(f"{BASE_API_URL}/activities/", headers=get_headers())
    activities = act_res.json() if act_res.status_code == 200 else []
    # Limit to last 20 activities for the dashboard
    activities = activities[:20]
            
    return render_template("dashboard.html", accounts=accounts, activities=activities)

@app.route("/create_account", methods=["POST"])
def create_account():
    if "token" not in session:
        return redirect("/")
    
    # Send a request to the backend with an initial balance of 0
    res = requests.post(f"{BASE_API_URL}/accounts/", json={"balance": 0.0}, headers=get_headers())
    if res.status_code != 200:
        flash("Erreur lors de la création du compte.")
        
    return redirect("/dashboard")

@app.route("/account/<account_number>")
def account_details(account_number):
    if "token" not in session:
        return redirect("/")
        
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200:
        return redirect("/dashboard")
    account = acc_res.json()
    
    tx_res = requests.get(f"{BASE_API_URL}/accounts/transactions/{account_number}", headers=get_headers())
    transactions = []
    if tx_res.status_code == 200:
        transactions = tx_res.json().get("transactions", [])
        
    ben_res = requests.get(f"{BASE_API_URL}/beneficiaries/", headers=get_headers())
    beneficiaries = ben_res.json() if ben_res.status_code == 200 else []
    
    # Fetch card-specific activities (filter by account_number)
    act_res = requests.get(f"{BASE_API_URL}/activities/", headers=get_headers())
    all_activities = act_res.json() if act_res.status_code == 200 else []
    card_activities = [a for a in all_activities if a.get("account_number") == account_number][:15]
        
    is_expired = is_card_expired(account.get("card_expiry"))
    
    return render_template("account_details.html", account=account, transactions=transactions, beneficiaries=beneficiaries, card_activities=card_activities, is_expired=is_expired)

@app.route("/account/<account_number>/card")
def card_details(account_number):
    if "token" not in session:
        return redirect("/")
        
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200:
        return redirect("/dashboard")
    account = acc_res.json()
    
    # Fetch card-specific activities (filter by account_number)
    act_res = requests.get(f"{BASE_API_URL}/activities/", headers=get_headers())
    all_activities = act_res.json() if act_res.status_code == 200 else []
    card_activities = [a for a in all_activities if a.get("account_number") == account_number][:20]
        
    is_expired = is_card_expired(account.get("card_expiry"))
    
    return render_template("card_details.html", account=account, card_activities=card_activities, is_expired=is_expired)

@app.route("/deposit", methods=["POST"])
@limiter.limit("10 per minute")
def deposit():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    amount = float(request.form.get("amount", 0))
    pin = request.form.get("pin", "")
    otp_code = request.form.get("otp_code", "")
    
    res = requests.post(f"{BASE_API_URL}/accounts/deposit", json={
        "account_number": account_number,
        "amount": amount,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code != 200:
        try:
            detail = res.json().get("detail", "Erreur lors du dépôt")
        except Exception:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")
    
    return redirect(f"/account/{account_number}")

@app.route("/withdraw", methods=["POST"])
@limiter.limit("10 per minute")
def withdraw():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    amount = float(request.form.get("amount", 0))
    pin = request.form.get("pin", "")
    otp_code = request.form.get("otp_code", "")
    is_foreign = request.form.get("is_foreign") == "on"
    is_contactless = request.form.get("is_contactless") == "on"
    
    res = requests.post(f"{BASE_API_URL}/accounts/withdraw", json={
        "account_number": account_number,
        "amount": amount,
        "pin": pin,
        "otp_code": otp_code,
        "is_foreign": is_foreign,
        "is_contactless": is_contactless
    }, headers=get_headers())
    
    if res.status_code != 200:
        try:
            detail = res.json().get("detail", "Erreur ou solde insuffisant")
        except Exception:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")
        
    return redirect(f"/account/{account_number}")

@app.route("/process_transfer", methods=["POST"])
@limiter.limit("10 per minute")
def process_transfer():
    if "token" not in session: return redirect("/")
    from_account = request.form.get("from_account")
    to_account = request.form.get("to_account")
    amount = float(request.form.get("amount", 0))
    pin = request.form.get("pin", "")
    otp_code = request.form.get("otp_code", "")
    
    res = requests.post(f"{BASE_API_URL}/accounts/transfer", json={
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code != 200:
        try:
            detail = res.json().get("detail", "Erreur durant le transfert")
        except Exception:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")
    else:
        flash("Transfert réussi!", "success")
        
    return redirect(f"/account/{from_account}")

@app.route("/process_payment", methods=["POST"])
@limiter.limit("10 per minute")
def process_payment():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    amount = float(request.form.get("amount", 0))
    merchant = request.form.get("merchant")
    pin = request.form.get("pin", "")
    otp_code = request.form.get("otp_code", "")
    is_online = request.form.get("is_online") == "on"
    is_foreign = request.form.get("is_foreign") == "on"
    is_contactless = request.form.get("is_contactless") == "on"
    
    res = requests.post(f"{BASE_API_URL}/accounts/payment", json={
        "account_number": account_number,
        "amount": amount,
        "merchant": merchant,
        "pin": pin,
        "otp_code": otp_code,
        "is_online": is_online,
        "is_foreign": is_foreign,
        "is_contactless": is_contactless
    }, headers=get_headers())
    
    if res.status_code != 200:
        try:
            detail = res.json().get("detail", "Erreur lors du paiement")
        except Exception:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")
    else:
        flash("Paiement effectué avec succès!", "success")
        
    return redirect(f"/account/{account_number}")

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if "token" not in session: return redirect("/")
    
    if request.method == "POST":
        current_password = request.form.get("current_password")
        otp_code = request.form.get("otp_code")
        
        new_username = request.form.get("new_username")
        new_lastname = request.form.get("new_lastname")
        new_password = request.form.get("new_password")
        new_email = request.form.get("new_email")
        new_phone = request.form.get("new_phone")
        
        # 1. Update Security (Profile & Password)
        payload_security = {
            "current_password": current_password,
            "otp_code": otp_code
        }
        has_security_update = False
        if new_username:
            payload_security["new_username"] = new_username
            has_security_update = True
        if new_lastname:
            payload_security["new_lastname"] = new_lastname
            has_security_update = True
        if new_password:
            payload_security["new_password"] = new_password
            has_security_update = True
        
        # 2. Update Contact (Email & Phone)
        payload_contact = {
            "current_password": current_password,
            "otp_code": otp_code
        }
        has_contact_update = False
        if new_email:
            payload_contact["new_email"] = new_email
            has_contact_update = True
        if new_phone:
            payload_contact["new_phone"] = new_phone
            has_contact_update = True

        success_msgs = []
        err_msgs = []
        
        if has_security_update:
            res_sec = requests.put(f"{BASE_API_URL}/users/me/security", json=payload_security, headers=get_headers())
            if res_sec.status_code == 200: success_msgs.append("Profil mis à jour.")
            else: err_msgs.append(res_sec.json().get("detail", "Erreur Profil"))
                
        if has_contact_update:
            res_con = requests.put(f"{BASE_API_URL}/users/me/contact", json=payload_contact, headers=get_headers())
            if res_con.status_code == 200: success_msgs.append("Contacts mis à jour.")
            else: err_msgs.append(res_con.json().get("detail", "Erreur Contacts"))

        if not has_security_update and not has_contact_update:
            flash("Aucune modification demandée.", "info")
        elif len(err_msgs) == 0:
            flash("Paramètres mis à jour avec succès !", "success")
        else:
            flash(" / ".join(err_msgs), "error")
            
    # GET user details
    res = requests.get(f"{BASE_API_URL}/users/me", headers=get_headers())
    user_data = res.json() if res.status_code == 200 else {}
    return render_template("settings.html", user=user_data)

@app.route("/settings/contact", methods=["POST"])
@limiter.limit("3 per minute")
def update_contact():
    if "token" not in session: return redirect("/")
    current_password = request.form.get("current_password")
    otp_code         = request.form.get("otp_code")
    new_email        = request.form.get("new_email") or None
    new_phone        = request.form.get("new_phone") or None

    payload = {"current_password": current_password, "otp_code": otp_code}
    if new_email:  payload["new_email"]  = new_email
    if new_phone:  payload["new_phone"]  = new_phone

    res = requests.put(f"{BASE_API_URL}/users/me/contact", json=payload, headers=get_headers())
    if res.status_code == 200:
        flash("Coordonnées mises à jour avec succès !", "success")
    else:
        detail = res.json().get("detail", "Erreur lors de la mise à jour")
        flash(detail if isinstance(detail, str) else str(detail), "error")
    return redirect("/settings")

@app.route("/beneficiaries", methods=["GET", "POST"])
def beneficiaries():
    if "token" not in session: return redirect("/")
    
    if request.method == "POST":
        account_number = request.form.get("account_number")
        alias = request.form.get("alias")
        current_password = request.form.get("current_password")
        otp_code = request.form.get("otp_code")
        
        res = requests.post(f"{BASE_API_URL}/beneficiaries/", json={
            "account_number": account_number,
            "alias": alias,
            "current_password": current_password,
            "otp_code": otp_code
        }, headers=get_headers())
        
        if res.status_code == 200:
            flash("Bénéficiaire ajouté avec succès !", "success")
        else:
            detail = res.json().get("detail", "Erreur lors de l'ajout")
            flash(detail if isinstance(detail, str) else str(detail), "error")
            
    # GET Bens
    res = requests.get(f"{BASE_API_URL}/beneficiaries/", headers=get_headers())
    bens = res.json() if res.status_code == 200 else []
    return render_template("beneficiaries.html", beneficiaries=bens)

@app.route("/journal")
def journal():
    if "token" not in session: return redirect("/")
    act_res = requests.get(f"{BASE_API_URL}/activities/", headers=get_headers())
    activities = act_res.json() if act_res.status_code == 200 else []
    return render_template("journal.html", activities=activities)

# ==========================================
# RIB / IBAN
# ==========================================

@app.route("/account/<account_number>/rib")
def account_rib(account_number):
    if "token" not in session: return redirect("/")
    res = requests.get(f"{BASE_API_URL}/accounts/{account_number}/rib", headers=get_headers())
    if res.status_code != 200:
        flash("Impossible de charger le RIB.", "error")
        return redirect(f"/account/{account_number}")
    rib_data = res.json()
    return render_template("rib.html", rib=rib_data, account_number=account_number)

@app.route("/account/<account_number>/rib/pdf")
def download_rib_pdf(account_number):
    if "token" not in session: return redirect("/")
    
    res = requests.get(f"{BASE_API_URL}/accounts/{account_number}/rib", headers=get_headers())
    if res.status_code != 200:
        flash("Erreur lors de la récupération des données du RIB.", "error")
        return redirect(f"/account/{account_number}/rib")
        
    rib = res.json()
    
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("helvetica", size=18, style='B')
    pdf.cell(0, 15, text="Relevé d'Identité Bancaire (RIB)", align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, text=f"Titulaire : {rib.get('owner_name', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Banque : {rib.get('bank_name', 'API Bank')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Code Banque : {rib.get('bank_code', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Code Agence : {rib.get('branch_code', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Numéro de Compte : {rib.get('account_number', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Clé RIB : {rib.get('rib_key', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"RIB Complet : {rib.get('rib', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(5)
    pdf.set_font("helvetica", size=14, style='B')
    pdf.cell(0, 10, text=f"IBAN : {rib.get('iban', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(20)
    pdf.set_font("helvetica", size=10, style='I')
    pdf.cell(0, 10, text="Ce document est généré électroniquement.", align='C', new_x="LMARGIN", new_y="NEXT")
    
    pdf_bytes = pdf.output()
    
    return send_file(
        BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"RIB_{account_number}.pdf"
    )

# ==========================================
# RECEIPT PDF
# ==========================================

@app.route("/account/<account_number>/receipt/<int:index>")
def download_receipt(account_number, index):
    if "token" not in session: return redirect("/")
    
    headers = get_headers()
    
    # Check access to account
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=headers)
    if acc_res.status_code != 200:
        flash("Accès non autorisé", "error")
        return redirect("/dashboard")

    tx_res = requests.get(f"{BASE_API_URL}/accounts/transactions/{account_number}", headers=headers)
    if tx_res.status_code != 200:
        flash("Impossible de récupérer les transactions", "error")
        return redirect(f"/account/{account_number}")
        
    transactions = tx_res.json().get("transactions", [])
    if index < 0 or index >= len(transactions):
        flash("Transaction introuvable", "error")
        return redirect(f"/account/{account_number}")
        
    tx = transactions[index]
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=16, style='B')
    pdf.cell(0, 15, text="Reçu de Transaction - API Bank", align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, text=f"Compte : **** **** **** {account_number[-4:]}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Date : {tx.get('timestamp', 'N/A')[:19]}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, text=f"Type d'operation : {tx.get('type', 'N/A').replace('_', ' ').upper()}", new_x="LMARGIN", new_y="NEXT")
    
    amount = float(tx.get('amount', 0))
    pdf.cell(0, 10, text=f"Montant : {amount:.2f} TND", new_x="LMARGIN", new_y="NEXT")
    
    if tx.get('type') == 'transfer':
        if tx.get('from_account') == account_number:
            pdf.cell(0, 10, text=f"Envoye a : {tx.get('to_account', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 10, text=f"Recu de : {tx.get('from_account', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    elif tx.get('merchant'):
        pdf.cell(0, 10, text=f"Commercant : {tx.get('merchant', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    elif tx.get('provider'):
        pdf.cell(0, 10, text=f"Fournisseur : {tx.get('provider', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
    if tx.get('reference'):
        pdf.cell(0, 10, text=f"Reference : {tx.get('reference', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
    pdf.ln(20)
    pdf.set_font("helvetica", size=10, style='I')
    pdf.cell(0, 10, text="Ce document est genere electroniquement et sert de preuve de transaction.", align='C', new_x="LMARGIN", new_y="NEXT")
    
    pdf_bytes = pdf.output()
    
    return send_file(
        BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"recu_{tx.get('type', 'transaction')}_{tx.get('timestamp', '')[:10]}.pdf"
    )

# ==========================================
# BILLS PAGE
# ==========================================

@app.route("/bills")
def bills():
    if "token" not in session: return redirect("/")
    res = requests.get(f"{BASE_API_URL}/accounts/", headers=get_headers())
    accounts = res.json() if res.status_code == 200 else []
    return render_template("bills.html", accounts=accounts)

@app.route("/pay_bill", methods=["POST"])
@limiter.limit("10 per minute")
def pay_bill():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    provider       = request.form.get("provider")
    category       = request.form.get("category")
    bill_reference = request.form.get("bill_reference")
    amount         = float(request.form.get("amount", 0))
    pin            = request.form.get("pin", "")
    otp_code       = request.form.get("otp_code", "")

    res = requests.post(f"{BASE_API_URL}/accounts/bill-payment", json={
        "account_number": account_number,
        "provider":       provider,
        "category":       category,
        "bill_reference": bill_reference,
        "amount":         amount,
        "pin":            pin,
        "otp_code":       otp_code
    }, headers=get_headers())

    if res.status_code == 200:
        flash(f"Facture {provider} payée avec succès !", "success")
    else:
        try:
            detail = res.json().get("detail", "Erreur lors du paiement")
        except:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")
    return redirect("/bills")

@app.route("/toggle_card_status", methods=["POST"])
def toggle_card_status():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/toggle-card-status", json={
        "account_number": account_number,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        msg = res.json().get("message", "Statut de la carte mis à jour.")
        flash(msg, "success")
    else:
        detail = res.json().get("detail", "Erreur lors du changement de statut")
        flash(detail, "error")
        
    return redirect(f"/card/{account_number}")

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/delete", json={
        "account_number": account_number,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash("Compte bancaire supprimé avec succès.", "success")
        return redirect("/dashboard")
    else:
        detail = res.json().get("detail", "Erreur lors de la suppression")
        flash(detail, "error")
        return redirect(f"/account/{account_number}")

@app.route("/delete_profile", methods=["POST"])
def delete_profile():
    if "token" not in session: return redirect("/")
    current_password = request.form.get("current_password")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/users/me/delete", json={
        "current_password": current_password,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        session.pop("token", None)
        flash("Votre profil et toutes vos données ont été supprimés.", "success")
        return redirect("/")
    else:
        detail = res.json().get("detail", "Erreur lors de la suppression du profil")
        flash(detail, "error")
        return redirect("/settings")

@app.route("/renew_card", methods=["POST"])
def renew_card():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/renew-card", json={
        "account_number": account_number,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash("Carte renouvelée avec succès. Les frais de 10 DT ont été prélevés.", "success")
    else:
        detail = res.json().get("detail", "Erreur lors du renouvellement")
        flash(detail, "error")
        
    return redirect(f"/card/{account_number}")

@app.route("/update_card_limits", methods=["POST"])
def update_card_limits():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    online_payment_limit = float(request.form.get("online_payment_limit", 1000))
    atm_withdrawal_limit = float(request.form.get("atm_withdrawal_limit", 500))
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/update-limits", json={
        "account_number": account_number,
        "online_payment_limit": online_payment_limit,
        "atm_withdrawal_limit": atm_withdrawal_limit,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash("Plafonds mis à jour avec succès.", "success")
    else:
        detail = res.json().get("detail", "Erreur lors de la mise à jour")
        flash(detail, "error")
    return redirect(f"/card/{account_number}")

@app.route("/update_card_options", methods=["POST"])
def update_card_options():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    contactless_payment = request.form.get("contactless_payment") == "on"
    internet_payments = request.form.get("internet_payments") == "on"
    foreign_transactions = request.form.get("foreign_transactions") == "on"
    domestic_withdrawals = request.form.get("domestic_withdrawals") == "on"
    foreign_withdrawals = request.form.get("foreign_withdrawals") == "on"
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/update-options", json={
        "account_number": account_number,
        "contactless_payment": contactless_payment,
        "internet_payments": internet_payments,
        "foreign_transactions": foreign_transactions,
        "domestic_withdrawals": domestic_withdrawals,
        "foreign_withdrawals": foreign_withdrawals,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash("Options de sécurité mises à jour.", "success")
    else:
        detail = res.json().get("detail", "Erreur lors de la mise à jour")
        flash(detail, "error")
    return redirect(f"/card/{account_number}")

@app.route("/update_card_subscription", methods=["POST"])
def update_card_subscription():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    subscription = request.form.get("subscription", "Standard")
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/update-subscription", json={
        "account_number": account_number,
        "subscription": subscription,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash(f"Abonnement mis à jour vers {subscription}.", "success")
    else:
        detail = res.json().get("detail", "Erreur lors de l'abonnement")
        flash(detail, "error")
    return redirect(f"/card/{account_number}")


@app.route("/support")
def support_page():
    if "token" not in session: return redirect("/")
    res = requests.get(f"{BASE_API_URL}/support/messages/history", headers=get_headers())
    messages = res.json() if res.status_code == 200 else []
    return render_template("messages.html", messages=messages)

@app.route("/support/chat", methods=["POST"])
def support_chat():
    if "token" not in session: return ("Unauthorized", 401)
    message = request.json.get("message")
    res = requests.post(f"{BASE_API_URL}/support/chat", json={"message": message}, headers=get_headers())
    return (res.content, res.status_code, {"Content-Type": "application/json"})

@app.route("/support/send_message", methods=["POST"])
def send_support_message():
    if "token" not in session: return redirect("/")
    subject = request.form.get("subject")
    category = request.form.get("category")
    content = request.form.get("content")
    
    res = requests.post(f"{BASE_API_URL}/support/messages/send", json={
        "subject": subject,
        "category": category,
        "content": content
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash("Message envoyé avec succès. Un conseiller vous répondra bientôt.", "success")
    else:
        detail = res.json().get("detail", "Erreur lors de l'envoi")
        flash(detail, "error")
        
    return redirect("/support")

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route("/admin/dashboard")
def admin_dashboard():
    if "token" not in session: return redirect("/")
    
    stats_res = requests.get(f"{BASE_API_URL}/admin/stats", headers=get_headers())
    if stats_res.status_code == 403:
        flash("Accès refusé. Privilèges administrateur requis.", "error")
        return redirect("/dashboard")
        
    stats = stats_res.json() if stats_res.status_code == 200 else {}
    
    act_res = requests.get(f"{BASE_API_URL}/admin/activities", headers=get_headers())
    activities = act_res.json() if act_res.status_code == 200 else []
    
    return render_template("admin_dashboard.html", stats=stats, activities=activities)

@app.route("/admin/messages")
def admin_messages():
    if "token" not in session: return redirect("/")
    
    msg_res = requests.get(f"{BASE_API_URL}/admin/messages", headers=get_headers())
    if msg_res.status_code == 403:
        flash("Accès refusé. Privilèges administrateur requis.", "error")
        return redirect("/dashboard")
        
    messages = msg_res.json() if msg_res.status_code == 200 else []
    return render_template("admin_messages.html", messages=messages)

@app.route("/admin/resolve_message/<msg_id>", methods=["POST"])
def admin_resolve_message(msg_id):
    if "token" not in session: return redirect("/")
    
    res = requests.put(f"{BASE_API_URL}/admin/messages/{msg_id}/resolve", headers=get_headers())
    if res.status_code == 200:
        flash("Message résolu avec succès.", "success")
    else:
        flash("Erreur lors de la résolution.", "error")
    return redirect("/admin/messages")

# ==========================================
# NEW FEATURES: Analytics, Simulation, Services
# ==========================================

@app.route("/account/<account_number>/analytics")
def account_analytics(account_number):
    if "token" not in session: return redirect("/")
    
    # Get account details
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200:
        return redirect("/dashboard")
    account = acc_res.json()
    
    # Get analytics data
    analytics_res = requests.get(f"{BASE_API_URL}/accounts/analytics/{account_number}", headers=get_headers())
    analytics = analytics_res.json() if analytics_res.status_code == 200 else {"categories": {}, "history": {}}

    return render_template("analytics.html", account=account, analytics=analytics)

@app.route("/credit_simulation")
def credit_simulation():
    if "token" not in session: return redirect("/")
    return render_template("credit_simulation.html")

@app.route("/account/<account_number>/services")
def account_services(account_number):
    if "token" not in session: return redirect("/")
    
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200:
        return redirect("/dashboard")
    account = acc_res.json()
    
    return render_template("services.html", account=account)

@app.route("/process_phone_recharge", methods=["POST"])
@limiter.limit("5 per minute")
def process_phone_recharge():
    if "token" not in session: return redirect("/")
    
    account_number = request.form.get("account_number")
    phone_number = request.form.get("phone_number")
    operator = request.form.get("operator")
    amount = float(request.form.get("amount", 0))
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/phone-recharge", json={
        "account_number": account_number,
        "phone_number": phone_number,
        "operator": operator,
        "amount": amount,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash(res.json().get("message", "Recharge effectuée."), "success")
    else:
        detail = res.json().get("detail", "Erreur lors de la recharge")
        flash(detail, "error")
        
    return redirect(f"/account/{account_number}/services")

@app.route("/request_checkbook", methods=["POST"])
@limiter.limit("3 per minute")
def request_checkbook():
    if "token" not in session: return redirect("/")
    
    account_number = request.form.get("account_number")
    type_pages = request.form.get("type")
    pin = request.form.get("pin")
    otp_code = request.form.get("otp_code")
    
    res = requests.post(f"{BASE_API_URL}/accounts/checkbook-request", json={
        "account_number": account_number,
        "type": type_pages,
        "pin": pin,
        "otp_code": otp_code
    }, headers=get_headers())
    
    if res.status_code == 200:
        flash(res.json().get("message", "Demande enregistrée."), "success")
    else:
        detail = res.json().get("detail", "Erreur lors de la demande")
        flash(detail, "error")
        
    return redirect(f"/account/{account_number}/services")


# ==========================================
# QR CODE PAYMENT
# ==========================================

@app.route("/account/<account_number>/qr-payment")
def qr_payment(account_number):
    if "token" not in session: return redirect("/")
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200:
        return redirect("/dashboard")
    account = acc_res.json()
    return render_template("qr_payment.html", account=account)

@app.route("/process_qr_payment", methods=["POST"])
@limiter.limit("10 per minute")
def process_qr_payment():
    if "token" not in session: return redirect("/")
    from_account = request.form.get("from_account")
    to_account   = request.form.get("to_account")
    amount       = float(request.form.get("amount", 0))
    pin          = request.form.get("pin", "")
    otp_code     = request.form.get("otp_code", "")

    res = requests.post(f"{BASE_API_URL}/accounts/transfer", json={
        "from_account": from_account,
        "to_account":   to_account,
        "amount":       amount,
        "pin":          pin,
        "otp_code":     otp_code
    }, headers=get_headers())

    if res.status_code == 200:
        flash(f"Paiement QR de {amount:.2f} TND effectué avec succès !", "success")
    else:
        try:
            detail = res.json().get("detail", "Erreur lors du paiement QR")
        except:
            detail = f"Erreur serveur ({res.status_code})"
        flash(detail, "error")

    return redirect(f"/account/{from_account}/qr-payment")


# ==========================================
# SCHEDULED / AUTOMATIC PAYMENTS
# ==========================================

import json, uuid
from datetime import datetime, date, timedelta
from pathlib import Path

SCHEDULED_FILE = Path(__file__).parent / "scheduled_payments.json"

def load_scheduled():
    if SCHEDULED_FILE.exists():
        try:
            return json.loads(SCHEDULED_FILE.read_text(encoding="utf-8"))
        except:
            return []
    return []

def save_scheduled(payments):
    SCHEDULED_FILE.write_text(json.dumps(payments, ensure_ascii=False, indent=2), encoding="utf-8")

def compute_next_date(current_next: str, frequency: str) -> str:
    """Advance next_date by one period."""
    try:
        d = datetime.strptime(current_next, "%Y-%m-%d").date()
        if frequency == "weekly":
            d += timedelta(weeks=1)
        elif frequency == "monthly":
            month = d.month + 1
            year  = d.year + (month - 1) // 12
            month = ((month - 1) % 12) + 1
            day   = min(d.day, [31,28+int((year%4==0 and year%100!=0) or year%400==0),31,30,31,30,31,31,30,31,30,31][month-1])
            d = date(year, month, day)
        elif frequency == "quarterly":
            month = d.month + 3
            year  = d.year + (month - 1) // 12
            month = ((month - 1) % 12) + 1
            d = date(year, month, d.day)
    except:
        pass
    return d.strftime("%Y-%m-%d")

def enrich_payment(p: dict) -> dict:
    """Add progress_pct and days_remaining for display."""
    try:
        nd = datetime.strptime(p["next_date"], "%Y-%m-%d").date()
        today = date.today()
        days_remaining = max(0, (nd - today).days)

        freq_days = {"once": 1, "weekly": 7, "monthly": 30, "quarterly": 90}
        total = freq_days.get(p["frequency"], 30)
        elapsed = total - days_remaining
        p["progress_pct"] = min(100, max(5, round(elapsed / total * 100)))
        p["days_remaining"] = days_remaining
    except:
        p["progress_pct"] = 50
        p["days_remaining"] = 0
    return p

def execute_due_payments(account_number: str, headers: dict):
    """Check and execute payments that are due today or overdue."""
    payments = load_scheduled()
    today = date.today().strftime("%Y-%m-%d")
    changed = False
    for p in payments:
        if p.get("account_number") != account_number: continue
        if p.get("status") != "active": continue
        if p.get("next_date", "9999") <= today:
            # Execute via transfer
            res = requests.post(f"{BASE_API_URL}/accounts/transfer", json={
                "from_account": p["account_number"],
                "to_account":   p["to_account"],
                "amount":       p["amount"],
                "pin":          p.get("pin", ""),
                "otp_code":     p.get("otp_code", "0000")
            }, headers=headers)
            if res.status_code == 200:
                if p["frequency"] == "once":
                    p["status"] = "done"
                else:
                    p["next_date"] = compute_next_date(p["next_date"], p["frequency"])
                changed = True
    if changed:
        save_scheduled(payments)

@app.route("/account/<account_number>/scheduled-payments")
def scheduled_payments(account_number):
    if "token" not in session: return redirect("/")
    acc_res = requests.get(f"{BASE_API_URL}/accounts/{account_number}", headers=get_headers())
    if acc_res.status_code != 200: return redirect("/dashboard")
    account = acc_res.json()

    # Execute any due payments silently
    execute_due_payments(account_number, get_headers())

    all_payments = load_scheduled()
    my_payments = [enrich_payment(p) for p in all_payments if p.get("account_number") == account_number]
    # Sort: active first, then paused, then done
    order = {"active": 0, "paused": 1, "done": 2}
    my_payments.sort(key=lambda p: (order.get(p.get("status", "done"), 3), p.get("next_date", "")))

    return render_template("scheduled_payments.html", account=account, payments=my_payments)

@app.route("/add_scheduled_payment", methods=["POST"])
@limiter.limit("5 per minute")
def add_scheduled_payment():
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    to_account     = request.form.get("to_account", "").strip()
    amount         = float(request.form.get("amount", 0))
    frequency      = request.form.get("frequency", "monthly")
    start_date     = request.form.get("start_date", date.today().strftime("%Y-%m-%d"))
    label          = request.form.get("label", "Paiement programmé")
    pin            = request.form.get("pin", "")
    otp_code       = request.form.get("otp_code", "")

    if not to_account or amount <= 0:
        flash("Données invalides.", "error")
        return redirect(f"/account/{account_number}/scheduled-payments")

    # Verify via a dummy transfer-check (OTP validation)
    verify_res = requests.post(f"{BASE_API_URL}/accounts/transfer", json={
        "from_account": account_number,
        "to_account":   to_account,
        "amount":       0.01,
        "pin":          pin,
        "otp_code":     otp_code
    }, headers=get_headers())

    # Accept if token valid (200 = OK, or we allow programming on 4xx account issues but not auth issues)
    if verify_res.status_code == 401:
        flash("Authentification invalide (PIN ou OTP incorrect).", "error")
        return redirect(f"/account/{account_number}/scheduled-payments")

    new_payment = {
        "id":             str(uuid.uuid4())[:8],
        "account_number": account_number,
        "to_account":     to_account,
        "amount":         amount,
        "frequency":      frequency,
        "next_date":      start_date,
        "label":          label,
        "pin":            pin,
        "otp_code":       otp_code,
        "status":         "active",
        "created_at":     date.today().strftime("%Y-%m-%d")
    }

    payments = load_scheduled()
    payments.append(new_payment)
    save_scheduled(payments)

    freq_labels = {"once": "unique", "weekly": "hebdomadaire", "monthly": "mensuel", "quarterly": "trimestriel"}
    flash(f"Paiement {freq_labels.get(frequency, frequency)} de {amount:.2f} TND programmé avec succès !", "success")
    return redirect(f"/account/{account_number}/scheduled-payments")

@app.route("/pause_scheduled_payment/<payment_id>", methods=["POST"])
def pause_scheduled_payment(payment_id):
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    payments = load_scheduled()
    for p in payments:
        if p["id"] == payment_id and p["account_number"] == account_number:
            p["status"] = "paused"
            break
    save_scheduled(payments)
    flash("Paiement mis en pause.", "success")
    return redirect(f"/account/{account_number}/scheduled-payments")

@app.route("/resume_scheduled_payment/<payment_id>", methods=["POST"])
def resume_scheduled_payment(payment_id):
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    payments = load_scheduled()
    for p in payments:
        if p["id"] == payment_id and p["account_number"] == account_number:
            p["status"] = "active"
            break
    save_scheduled(payments)
    flash("Paiement repris.", "success")
    return redirect(f"/account/{account_number}/scheduled-payments")

@app.route("/cancel_scheduled_payment/<payment_id>", methods=["POST"])
def cancel_scheduled_payment(payment_id):
    if "token" not in session: return redirect("/")
    account_number = request.form.get("account_number")
    payments = load_scheduled()
    payments = [p for p in payments if not (p["id"] == payment_id and p["account_number"] == account_number)]
    save_scheduled(payments)
    flash("Paiement programmé annulé.", "success")
    return redirect(f"/account/{account_number}/scheduled-payments")

if __name__ == "__main__":
    app.run(port=5000, debug=True)
