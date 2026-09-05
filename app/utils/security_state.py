"""
security_state.py — État global de la sécurité (Pare-feu applicatif)
Blocage DÉFINITIF des adresses IP jusqu'à déblocage manuel par l'administrateur.
"""
import time
import threading

# Dictionnaire {ip: {"blocked_at": timestamp_str, "reason": str}}
_blocked_ips = {}
_lock = threading.Lock()

# Whitelist des IPs internes (Docker, Gateway, Localhost)
WHITELISTED_IPS = ["127.0.0.1", "0.0.0.0"]

def block_ip(ip: str, reason: str = "Blocage Administrateur / SIEM"):
    """Bloque une IP définitivement jusqu'à intervention manuelle de l'administrateur."""
    # Ne jamais bloquer les IPs internes de l'infrastructure
    if ip in WHITELISTED_IPS or ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[Firewall] Tentative de blocage ignorée pour l'IP interne: {ip}")
        return
        
    with _lock:
        blocked_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        _blocked_ips[ip] = {
            "blocked_at": blocked_at,
            "reason": reason,
            "status": "BLOCKED_DEFINITIVELY"
        }
        print(f"[Firewall] IP {ip} bloquée DÉFINITIVEMENT à {blocked_at} (jusqu'à déblocage manuel par l'administrateur).")

def is_ip_blocked(ip: str) -> bool:
    """Vérifie si l'IP est dans la liste des IPs bloquées définitivement."""
    with _lock:
        return ip in _blocked_ips

def unblock_ip(ip: str):
    """Déblocage manuel immédiat par l'administrateur."""
    with _lock:
        if ip in _blocked_ips:
            del _blocked_ips[ip]
            print(f"[Firewall] IP {ip} débloquée manuellement par l'administrateur.")

def get_blocked_ips():
    """Retourne la liste de toutes les IPs actuellement bloquées définitivement."""
    with _lock:
        result = []
        for ip, info in _blocked_ips.items():
            result.append({
                "ip": ip,
                "status": "Bloqué Définitivement",
                "blocked_at": info.get("blocked_at", "N/A"),
                "reason": info.get("reason", "Manuel / SIEM"),
                "remaining_minutes": "Permanent",
                "expires_at": "Jusqu'au déblocage manuel"
            })
        return result
