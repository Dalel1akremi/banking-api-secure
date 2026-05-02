"""
alert_store.py — Stockage thread-safe des alertes de sécurité.
Utilisé comme bus de communication entre le thread de surveillance
et l'endpoint SSE.
"""
import threading
from collections import deque
from datetime import datetime

_lock = threading.Lock()
_alerts = deque(maxlen=200)  # Keep last 200 alerts
_counter = 0


def add_alert(alert_type: str, severity: str, ip: str, message: str, source: str = "HTTP"):
    """Ajouter une nouvelle alerte de façon thread-safe."""
    global _counter
    with _lock:
        alert = {
            "id": _counter,
            "type": alert_type,
            "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW
            "ip": ip,
            "message": message,
            "source": source,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        _alerts.append(alert)
        _counter += 1
        return alert


def get_alerts_since(last_id: int):
    """Récupérer toutes les alertes dont l'ID est supérieur à last_id."""
    with _lock:
        return [a for a in _alerts if a["id"] > last_id]


def get_recent_alerts(limit: int = 10):
    """Récupérer les N dernières alertes."""
    with _lock:
        alerts = list(_alerts)
        return alerts[-limit:]


def get_alert_count():
    """Retourner le compteur global pour synchronisation."""
    with _lock:
        return _counter
