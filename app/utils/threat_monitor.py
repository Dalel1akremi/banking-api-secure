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

# Seuils de détection
BRUTE_FORCE_THRESHOLD = 3   # Nombre d'échecs 401 dans la fenêtre
RATE_ABUSE_THRESHOLD = 2    # Nombre de 429 dans la fenêtre
FORBIDDEN_THRESHOLD = 3     # Nombre d'accès 403

# État interne du moniteur
_ip_auth_failures = defaultdict(list)   # IP -> [timestamps]
_ip_rate_limits = defaultdict(list)     # IP -> [timestamps]
_ip_forbidden = defaultdict(list)       # IP -> [timestamps]
_alerted_ips = set()                    # IPs déjà alertées (évite duplicats)

# Regex
_LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>.*?)\] \| (?P<level>.*?) \| IP: (?P<ip>.*?) \| METHOD: (?P<method>.*?) \| PATH: (?P<path>.*?) \| STATUS: (?P<status>\d+)"
)


def _send_email_alert(subject: str, body: str):
    """Envoyer un email d'alerte à l'administrateur."""
    if not GMAIL_SENDER or not GMAIL_APP_PASSWORD:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [API Bank SIEM] {subject}"
        msg["From"] = GMAIL_SENDER
        msg["To"] = GMAIL_SENDER

        html = f"""
        <html><body style="font-family: sans-serif; background:#0f172a; color:#e2e8f0; padding:20px;">
        <div style="max-width:600px; margin:auto; background:#1e293b; border-radius:12px; padding:24px; border-left:4px solid #ef4444;">
            <h2 style="color:#ef4444; margin:0 0 16px;">🚨 Alerte de Sécurité — API Bank</h2>
            <p style="font-size:16px;">{body}</p>
            <p style="color:#64748b; font-size:12px; margin-top:24px;">
                Généré automatiquement par le système SIEM · {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>
        </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_SENDER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_SENDER, GMAIL_SENDER, msg.as_string())
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
            _ip_auth_failures[ip].append(now_str)
            if len(_ip_auth_failures[ip]) >= BRUTE_FORCE_THRESHOLD:
                count = len(_ip_auth_failures[ip])
                msg = f"Brute force détecté depuis {ip} : {count} tentatives de connexion échouées sur /auth/login."
                add_alert("brute_force", "CRITICAL", ip, msg, source="HTTP Log")
                _send_email_alert("Brute Force Détecté", msg)
                _ip_auth_failures[ip] = []  # Reset pour permettre la détection de la série suivante

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
            alert_key = f"rl_{ip}"
            if alert_key not in _alerted_ips:
                _alerted_ips.add(alert_key)
                msg = f"Abus de débit (Rate Limit) depuis {ip} : {count} dépassements de quota sur {path}."
                add_alert("rate_limit_abuse", "HIGH", ip, msg, source="HTTP Log")
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
