"""
security_state.py — État global de la sécurité (Pare-feu applicatif en mémoire)
Blocage temporaire des adresses IP pendant 15 minutes avec possibilité de déblocage manuel par l'administrateur.
"""
import time
import threading

BLOCK_DURATION_SECONDS = 15 * 60  # 15 minutes

# Dictionnaire {ip: unblock_timestamp}
_blocked_ips = {}
_lock = threading.Lock()

# Whitelist des IPs internes (Docker, Gateway, Localhost)
WHITELISTED_IPS = ["127.0.0.1", "0.0.0.0"]

def block_ip(ip: str, duration_seconds: int = BLOCK_DURATION_SECONDS):
    # Ne jamais bloquer les IPs internes de l'infrastructure
    if ip in WHITELISTED_IPS or ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[Firewall] Tentative de blocage ignorée pour l'IP interne: {ip}")
        return
        
    with _lock:
        expiry_time = time.time() + duration_seconds
        _blocked_ips[ip] = expiry_time
        print(f"[Firewall] IP {ip} bloquée pour {duration_seconds // 60} minutes (jusqu'à {time.strftime('%H:%M:%S', time.localtime(expiry_time))}).")

def is_ip_blocked(ip: str) -> bool:
    with _lock:
        if ip in _blocked_ips:
            # Vérifier si les 15 minutes sont écoulées
            if time.time() < _blocked_ips[ip]:
                return True
            else:
                # 15 minutes écoulées : levée automatique du blocage
                del _blocked_ips[ip]
                print(f"[Firewall] Le blocage temporaire de 15 minutes pour l'IP {ip} a expiré. IP débloquée.")
                return False
        return False

def unblock_ip(ip: str):
    """Déblocage manuel immédiat par l'administrateur."""
    with _lock:
        if ip in _blocked_ips:
            del _blocked_ips[ip]
            print(f"[Firewall] IP {ip} débloquée manuellement par l'administrateur.")

def get_blocked_ips():
    """Retourne la liste des IPs actuellement bloquées avec le temps restant."""
    with _lock:
        now = time.time()
        # Nettoyer les expirés
        expired = [ip for ip, exp in _blocked_ips.items() if now >= exp]
        for ip in expired:
            del _blocked_ips[ip]
            
        result = []
        for ip, exp in _blocked_ips.items():
            remaining_secs = max(0, int(exp - now))
            result.append({
                "ip": ip,
                "remaining_seconds": remaining_secs,
                "remaining_minutes": max(1, (remaining_secs + 59) // 60),
                "expires_at": time.strftime("%H:%M:%S", time.localtime(exp))
            })
        return result
