"""
security_state.py — État global de la sécurité (Pare-feu applicatif en mémoire)
"""
import threading

# Set des adresses IP bloquées (manuel ou auto)
_blocked_ips = set()
_lock = threading.Lock()

# Whitelist des IPs internes (Docker, Gateway, Localhost)
WHITELISTED_IPS = ["127.0.0.1", "0.0.0.0"]

def block_ip(ip: str):
    # Ne jamais bloquer les IPs internes de l'infrastructure
    if ip in WHITELISTED_IPS or ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[Firewall] Tentative de blocage ignorée pour l'IP interne: {ip}")
        return
        
    with _lock:
        _blocked_ips.add(ip)

def is_ip_blocked(ip: str) -> bool:
    with _lock:
        return ip in _blocked_ips

def unblock_ip(ip: str):
    with _lock:
        if ip in _blocked_ips:
            _blocked_ips.remove(ip)

def get_blocked_ips():
    with _lock:
        return list(_blocked_ips)
