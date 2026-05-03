"""
threat_monitor.py — Thread de surveillance en temps réel de security_audit.log.
Détecte les menaces et les pousse dans alert_store.
"""
import os
import re
import time
import threading
import smtplib
from collections import defaultdict
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

from app.utils.alert_store import add_alert

load_dotenv()

LOG_FILE = "security_audit.log"
CHECK_INTERVAL = 10  # secondes entre chaque vérification

GMAIL_SENDER = os.getenv("GMAIL_SENDER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

from app.db import users_collection

def _get_admin_email():
    """Récupérer l'email de l'administrateur (supporte booléen ou chaîne "true")."""
    admin = users_collection.find_one({"is_admin": {"$in": [True, "true"]}})
    return admin.get("email") if admin else GMAIL_SENDER

# Seuils de détection
BRUTE_FORCE_THRESHOLD = 3   # Nombre d'échecs 401 dans la fenêtre
RATE_ABUSE_THRESHOLD = 1    # Alerter dès le premier 429 détecté
FORBIDDEN_THRESHOLD = 3     # Nombre d'accès 403

# État interne du moniteur
_ip_auth_failures = defaultdict(list)   # IP -> [timestamps]
_ip_rate_limits = defaultdict(list)     # IP -> [timestamps]
_ip_forbidden = defaultdict(list)       # IP -> [timestamps]
_alerted_ips = set()                    # IPs déjà alertées (évite duplicats)

# Regex
_LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>.*?)\] \| (?P<level>.*?) \| IP: (?P<ip>.*?) \| METHOD: (?P<method>.*?) \| PATH: (?P<path>.*?) \| STATUS: (?P<status>\d+).*?(?: \| TARGET_EMAIL: (?P<email>.*?))?$"
)


def _send_email_alert(subject: str, body: str, recipient=None):
    """Envoyer un email d'alerte à l'administrateur ou à un utilisateur spécifique."""
    target = recipient if recipient else _get_admin_email()
    if not GMAIL_SENDER or not GMAIL_APP_PASSWORD or not target:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [API Bank SIEM] {subject}"
        msg["From"] = f"Sécurité API Bank <{GMAIL_SENDER}>"
        msg["To"] = target

        html = f"""
        <html><body style="font-family: sans-serif; background:#0f172a; color:#e2e8f0; padding:20px;">
        <div style="max-width:600px; margin:auto; background:#1e293b; border-radius:12px; padding:24px; border-left:4px solid #ef4444;">
            <h2 style="color:#ef4444; margin:0 0 16px;">🚨 Alerte de Sécurité — API Bank</h2>
            <p style="font-size:16px;">{body}</p>
            <p style="color:#64748b; font-size:12px; margin-top:24px;">
                Ceci est une notification automatique de sécurité. Si vous n'êtes pas à l'origine de cette activité, veuillez contacter le support immédiatement.
                <br><br>
                Généré par le système SIEM · {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>
        </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_SENDER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_SENDER, target, msg.as_string())
    except Exception as e:
        print(f"[ThreatMonitor] Email error: {e}")


def _analyze_line(line: str):
    """Analyser une ligne de log et déclencher des alertes si nécessaire."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Tentatives d'authentification échouées (401)
    match = _LOG_PATTERN.search(line)
    if match:
        status = int(match.group("status"))
        ip = match.group("ip")
        path = match.group("path")

        if (status == 401 or status == 422) and "/auth/login" in path:
            email = match.group("email")
            if email: email = email.strip()
            _ip_auth_failures[ip].append({"time": now_str, "email": email})
            
            if len(_ip_auth_failures[ip]) >= BRUTE_FORCE_THRESHOLD:
                count = len(_ip_auth_failures[ip])
                msg = f"Brute force détecté depuis {ip} : {count} tentatives de connexion échouées sur /auth/login."
                
                # Récupérer le dernier email valide de la série
                valid_emails = [f["email"] for f in _ip_auth_failures[ip] if f["email"]]
                last_email = valid_emails[-1] if valid_emails else None
                
                if last_email:
                    msg += f" Dernier compte ciblé : {last_email}"
                
                add_alert("brute_force", "CRITICAL", ip, msg, source="HTTP Log")
                
                # Notify Admin
                _send_email_alert("Alerte Brute Force - Administrateur", msg)
                print(f"[ThreatMonitor] Sent Admin Alert for Brute Force.")
                
                # Notify targeted User if email exists in DB
                if last_email:
                    print(f"[ThreatMonitor] Looking up user in DB for email: '{last_email}'")
                    target_user = users_collection.find_one({"email": last_email})
                    if target_user:
                        print(f"[ThreatMonitor] User found in DB! Sending warning email to {last_email}")
                        user_msg = f"""
                        Bonjour,
                        <br><br>
                        Notre système de sécurité a bloqué plusieurs tentatives de connexion avec un mot de passe erroné sur votre compte depuis l'adresse IP {ip}.
                        <br><br>
                        <strong>S'agit-il bien de vous ?</strong>
                        <br>
                        Si c'est le cas et que vous avez oublié votre mot de passe, ne vous inquiétez pas. Vous pouvez lancer la procédure de récupération :
                        <ul>
                            <li>Rendez-vous sur la page de connexion.</li>
                            <li>Cliquez sur "Mot de passe oublié".</li>
                            <li>Suivez les instructions pour réinitialiser votre accès en toute sécurité.</li>
                        </ul>
                        <br>
                        <strong>Si ce n'est pas vous</strong>, votre compte pourrait être la cible d'une attaque malveillante. L'administrateur a déjà été alerté et votre compte est actuellement sous surveillance. Aucune action n'est requise de votre part tant que vous ne partagez pas vos codes secrets.
                        """
                        _send_email_alert("Alerte de Sécurité : Tentatives de connexion sur votre compte", user_msg, recipient=last_email)
                    else:
                        print(f"[ThreatMonitor] User NOT found in DB for email: '{last_email}'")
                else:
                    print(f"[ThreatMonitor] No valid email found to notify user.")
                
                _ip_auth_failures[ip] = []

        elif status == 403:
            _ip_forbidden[ip].append(now_str)
            if len(_ip_forbidden[ip]) >= FORBIDDEN_THRESHOLD:
                count = len(_ip_forbidden[ip])
                alert_key = f"fb_{ip}_{path}"
                if alert_key not in _alerted_ips:
                    _alerted_ips.add(alert_key)
                    msg = f"Accès interdit répété depuis {ip} : {count} erreurs 403 sur {path}."
                    add_alert("unauthorized_access", "HIGH", ip, msg, source="HTTP Log")
                    _ip_forbidden[ip] = []

    # Rate Limit (429) detection - ONLY on WARNING level to avoid duplicates
    if match and int(match.group("status")) == 429 and match.group("level") == "WARNING":
        ip = match.group("ip")
        path = match.group("path")
        _ip_rate_limits[ip].append(now_str)
        if len(_ip_rate_limits[ip]) >= RATE_ABUSE_THRESHOLD:
            count = len(_ip_rate_limits[ip])
            msg = f"Abus de débit (Rate Limit) depuis {ip} : {count} dépassements de quota sur {path}."
            add_alert("rate_limit_abuse", "HIGH", ip, msg, source="HTTP Log")
            
            # Notify Admin for Rate Limit
            _send_email_alert("Alerte Rate Limit - Administrateur", msg)
            
            _ip_rate_limits[ip] = []


def _monitor_loop():
    """Boucle principale du thread de surveillance."""
    print("[ThreatMonitor] Démarrage de la surveillance en temps réel...")

    last_position = 0
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            # Analyser les 100 dernières lignes au démarrage pour ne rien rater
            lines = f.readlines()
            for line in lines[-100:]:
                _analyze_line(line)
            
            f.seek(0, 2)  # Se repositionner à la fin pour la suite
            last_position = f.tell()

    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            if not os.path.exists(LOG_FILE):
                continue

            with open(LOG_FILE, "r") as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()

            for line in new_lines:
                _analyze_line(line)

        except Exception as e:
            print(f"[ThreatMonitor] Erreur: {e}")


def start_monitor():
    """Démarrer le thread de surveillance en arrière-plan."""
    thread = threading.Thread(target=_monitor_loop, daemon=True)
    thread.start()
    print("[ThreatMonitor] Thread démarré en arrière-plan.")
