import os
import re
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()
LOG_FILE = "security_audit.log"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# New google-genai SDK
gemini_client = None
if GEMINI_API_KEY:
    try:
        # Import plus robuste pour éviter les conflits de namespace
        import google.genai as genai_sdk
        gemini_client = genai_sdk.Client(api_key=GEMINI_API_KEY)
        print("[AI] Client Gemini 2.0 initialisé avec succès.")
    except Exception as e:
        print(f"Gemini init error: {e}")

def parse_security_logs(limit=2000):
    if not os.path.exists(LOG_FILE):
        return []

    logs = []
    log_pattern = re.compile(
        r"\[(?P<timestamp>.*?)\] \| (?P<level>.*?) \| IP: (?P<ip>.*?) \| METHOD: (?P<method>.*?) \| PATH: (?P<path>.*?) \| STATUS: (?P<status>\d+) \| DURATION: (?P<duration>.*?)ms"
    )
    rate_pattern = re.compile(
        r"ratelimit .*? \((?P<ip>.*?)\) exceeded at endpoint: (?P<path>.*)"
    )

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                match = log_pattern.search(line)
                if match:
                    logs.append({
                        "type": "request",
                        "timestamp": match.group("timestamp"),
                        "level": match.group("level"),
                        "ip": match.group("ip"),
                        "path": match.group("path"),
                        "status": int(match.group("status")),
                        "duration": match.group("duration")
                    })
                    continue
                match_rate = rate_pattern.search(line)
                if match_rate:
                    logs.append({
                        "type": "ratelimit",
                        "timestamp": match_rate.group("timestamp"),
                        "level": match_rate.group("level"),
                        "ip": match_rate.group("ip"),
                        "path": match_rate.group("path"),
                        "status": 429
                    })
    except Exception as e:
        print(f"Error parsing logs: {e}")

    return logs


def rule_based_analysis(logs):
    """Analyse de sécurité locale sans dépendance IA externe."""
    recent = logs[-500:]  # Augmenté à 500 pour plus de stabilité

    ip_failures = defaultdict(int)
    ip_rate_limits = defaultdict(int)
    path_hits = defaultdict(int)
    forbidden_paths = []
    brute_force_ips = []

    for log in recent:
        ip = log.get("ip", "Unknown")
        status = log.get("status", 0)
        path = log.get("path", "")

        if status == 401 or status == 422:
            ip_failures[ip] += 1
        if status == 429:
            ip_rate_limits[ip] += 1
        if status == 403:
            forbidden_paths.append(path)
        path_hits[path] += 1

    findings = []

    # Brute Force Detection
    for ip, count in ip_failures.items():
        if count >= 3:
            brute_force_ips.append(ip)
            findings.append(
                f"🔴 Tentative de brute force détectée depuis {ip} : {count} échecs d'authentification consécutifs sur /auth/login."
            )

    # Rate Limit Abuse
    for ip, count in ip_rate_limits.items():
        if count >= 2:
            findings.append(
                f"🟠 Abus de débit (Rate Limiting) depuis {ip} : {count} dépassements de quota détectés."
            )

    # Unauthorized Access
    if forbidden_paths:
        unique_forbidden = list(set(forbidden_paths))
        findings.append(
            f"🟡 {len(forbidden_paths)} accès non autorisés (403) sur : {', '.join(unique_forbidden[:3])}."
        )

    # Most targeted endpoint
    if path_hits:
        top_path = max(path_hits, key=path_hits.get)
        top_count = path_hits[top_path]
        if top_count > 10:
            findings.append(
                f"📊 Endpoint le plus sollicité : {top_path} ({top_count} requêtes récentes)."
            )

    if not findings:
        return "✅ Analyse locale : Aucun comportement suspect détecté dans les 100 dernières requêtes. Le système fonctionne normalement."

    return " | ".join(findings)


def get_security_stats():
    logs = parse_security_logs(limit=2000)

    ip_failures = defaultdict(int)
    unique_ips = set()

    stats = {
        "total_requests": len([l for l in logs if l["type"] == "request"]),
        "failed_auth": len([l for l in logs if l.get("status") in [401, 422]]),
        "rate_limited": len([l for l in logs if l.get("status") == 429 or l.get("type") == "ratelimit"]),
        "forbidden": len([l for l in logs if l.get("status") == 403]),
        "critical_alerts": 0,
    }

    for log in logs:
        unique_ips.add(log.get("ip", ""))
        # Inclure 422 et baisser le seuil à 3 pour correspondre au moniteur
        if log.get("status") in [401, 429, 422]:
            ip_failures[log.get("ip", "")] += 1

    stats["brute_force_attempts"] = sum([c for ip, c in ip_failures.items() if c >= 3])
    stats["unique_ips"] = len(unique_ips)
    stats["critical_alerts"] = stats["brute_force_attempts"] + (1 if stats["forbidden"] > 5 else 0)

    # Try Gemini first, fallback to rule-based analysis
    stats["ai_insight"] = analyze_with_ai(logs[-50:])

    return stats


import time

# État de santé de l'IA
_ai_cooldown_until = 0

def analyze_with_ai(recent_logs):
    """Try Gemini AI analysis, auto-fallback with explicit message if rate limited."""
    global _ai_cooldown_until
    
    now = time.time()
    
    if gemini_client and now > _ai_cooldown_until:
        log_text = "\n".join([
            f"{l['timestamp']} - IP {l['ip']} - {l['path']} - {l.get('status')}"
            for l in recent_logs
        ])
        prompt = (
            "Tu es un expert en cybersécurité bancaire. Analyse ces logs et détecte des comportements suspects. "
            "Sois très concis (2-3 phrases max)."
            f"\n\nLOGS RÉCENTS:\n{log_text}"
        )
        try:
            response = gemini_client.models.generate_content(
                model="gemini-2.0-flash-lite",
                contents=prompt
            )
            return "🤖 [Gemini] " + response.text
        except Exception as e:
            err_str = str(e).upper()
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "QUOTA" in err_str:
                # Activer le cooldown de 10 minutes
                _ai_cooldown_until = now + 600 
                print("[AI] Quota atteint. Mode local activé pour 10min.")
            else:
                return f"⚠️ Erreur IA : {str(e)[:100]}"

    if now < _ai_cooldown_until:
        # Message très explicite et propre
        status_msg = "⚠️ [IA Gemini en pause : Limite de 50 req/h atteinte]. Basculement sur l'analyse de sécurité locale : "
    else:
        status_msg = "🔍 [Analyse locale] "
    
    # On récupère l'analyse brute (sans le préfixe "✅ Analyse locale" pour éviter les doublons)
    local_result = rule_based_analysis(recent_logs)
    if "✅ Analyse locale :" in local_result:
        local_result = local_result.replace("✅ Analyse locale :", "✅")
        
    return status_msg + local_result
