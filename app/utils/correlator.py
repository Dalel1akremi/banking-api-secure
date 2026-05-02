"""
correlator.py — Corrélation multi-sources entre logs HTTP et MongoDB.
Croise les données de 3 sources pour détecter des menaces invisibles
si on regarde chaque source séparément.
"""
from collections import defaultdict
from datetime import datetime, timedelta
from app.db import activity_logs_collection, users_collection, transactions_collection
from app.utils.security_analyzer import parse_security_logs
from app.utils.alert_store import add_alert


def run_correlation():
    """
    Corrélation multi-sources :
    Source 1 : HTTP logs (security_audit.log)
    Source 2 : MongoDB activity_logs (actions bancaires)
    Source 3 : MongoDB users (comptes bloqués / suspects)
    """
    results = []

    # ── Source 1 : Récupérer les IPs avec erreurs HTTP récentes ──────────────
    http_logs = parse_security_logs(limit=500)
    http_errors = defaultdict(list)  # ip -> [status codes]

    for log in http_logs:
        status = log.get("status", 0)
        if status in [401, 403, 429]:
            http_errors[log["ip"]].append(status)

    # ── Source 2 : Comptes avec transactions rejetées récemment ──────────────
    recent_cutoff = datetime.utcnow() - timedelta(hours=2)
    failed_txs = list(transactions_collection.find(
        {"timestamp": {"$gte": recent_cutoff.isoformat()},
         "type": {"$in": ["payment", "transfer", "withdraw"]}},
        {"account_number": 1, "amount": 1, "type": 1}
    ).limit(100))

    accounts_with_failures = {tx.get("account_number") for tx in failed_txs}

    # ── Source 3 : Utilisateurs bloqués ──────────────────────────────────────
    blocked_users = list(users_collection.find(
        {"status": "BLOCKED"},
        {"email": 1, "username": 1}
    ))
    blocked_count = len(blocked_users)

    # ── Corrélation : IPs suspectes + activité MongoDB ────────────────────────
    for ip, errors in http_errors.items():
        error_count = len(errors)
        auth_failures = errors.count(401)
        rate_blocks = errors.count(429)

        threat_score = 0
        threat_details = []

        if auth_failures >= 3:
            threat_score += 40
            threat_details.append(f"{auth_failures} échecs d'auth HTTP")

        if rate_blocks >= 2:
            threat_score += 30
            threat_details.append(f"{rate_blocks} rate limits déclenchés")

        if error_count >= 5:
            threat_score += 20
            threat_details.append(f"{error_count} erreurs totales")

        # Bonus si des comptes ont des transactions échouées (même fenêtre temps)
        if accounts_with_failures and auth_failures >= 2:
            threat_score += 20
            threat_details.append(f"+ {len(accounts_with_failures)} comptes avec transactions rejetées")

        if threat_score >= 60:
            severity = "CRITICAL" if threat_score >= 80 else "HIGH"
            description = f"IP {ip} — Score de menace: {threat_score}/100. " + " | ".join(threat_details)

            results.append({
                "ip": ip,
                "score": threat_score,
                "severity": severity,
                "description": description,
                "sources": ["HTTP Log", "MongoDB Transactions"]
            })

            # Pousser dans l'alert store si score élevé
            if threat_score >= 70:
                add_alert(
                    "correlation",
                    severity,
                    ip,
                    f"[CORRÉLATION] {description}",
                    source="Multi-Sources"
                )

    # ── Alerte sur les comptes bloqués ────────────────────────────────────────
    if blocked_count > 0:
        results.append({
            "ip": "N/A",
            "score": 50,
            "severity": "MEDIUM",
            "description": f"{blocked_count} compte(s) utilisateur(s) actuellement bloqué(s) dans le système.",
            "sources": ["MongoDB Users"]
        })

    return {
        "threats": sorted(results, key=lambda x: x["score"], reverse=True),
        "blocked_users": blocked_count,
        "accounts_with_failures": len(accounts_with_failures),
        "total_http_suspicious_ips": len(http_errors),
        "last_run": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
