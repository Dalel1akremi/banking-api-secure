from flask import Flask, render_template, request, redirect, session, flash
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = "secretkey"

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
    verification_code = request.form["verification_code"]

    res = requests.post(f"{BASE_API_URL}/users/", json={
        "username": username,
        "lastname": lastname,
        "cin": cin,
        "email": email,
        "password": password,
        "verification_code": verification_code
    })

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
        return render_template("signup.html", username=username, lastname=lastname, cin=cin, email=email)

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
        
        payload = {
            "current_password": current_password,
            "otp_code": otp_code
        }
        if new_username: payload["new_username"] = new_username
        if new_lastname: payload["new_lastname"] = new_lastname
        if new_password: payload["new_password"] = new_password
        
        res = requests.put(f"{BASE_API_URL}/users/me/security", json=payload, headers=get_headers())
        if res.status_code == 200:
            flash("Paramètres mis à jour avec succès !", "success")
        else:
            detail = res.json().get("detail", "Erreur lors de la mise à jour")
            flash(detail if isinstance(detail, str) else str(detail), "error")
            
    # GET user details
    res = requests.get(f"{BASE_API_URL}/users/me", headers=get_headers())
    user_data = res.json() if res.status_code == 200 else {}
    return render_template("settings.html", user=user_data)

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

if __name__ == "__main__":
    app.run(port=5000, debug=True)
