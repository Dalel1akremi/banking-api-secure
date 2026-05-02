"""
alerts.py — Endpoint SSE pour les alertes de sécurité en temps réel.
Le navigateur de l'admin se connecte une fois et reçoit les alertes
automatiquement sans recharger la page.
"""
import json
import asyncio

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.security.auth import verify_token
from app.utils.alert_store import get_alerts_since, get_recent_alerts
from app.utils.correlator import run_correlation

router = APIRouter(prefix="/admin", tags=["Alerts"])


def verify_admin(user=Depends(verify_token)):
    from fastapi import HTTPException
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accès refusé.")
    return user


@router.get("/alerts/stream")
async def alerts_stream(admin=Depends(verify_admin)):
    """
    Endpoint SSE — Connexion persistante.
    Le client envoie son last_id via query param pour ne pas recevoir
    les alertes déjà vues.
    """
    async def event_generator():
        last_id = -1

        # Message de connexion initial
        yield f"data: {json.dumps({'type': 'connected', 'message': '✅ Connecté au flux de surveillance SIEM en temps réel.'})}\n\n"

        while True:
            # Récupérer les nouvelles alertes depuis le dernier id connu
            new_alerts = get_alerts_since(last_id)

            for alert in new_alerts:
                last_id = alert["id"]
                yield f"data: {json.dumps(alert)}\n\n"

            # Envoyer un heartbeat toutes les 30s pour maintenir la connexion
            yield f": heartbeat\n\n"

            await asyncio.sleep(5)  # Polling toutes les 5 secondes

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Désactive le buffering NGINX
            "Connection": "keep-alive",
        }
    )


@router.get("/alerts/recent")
def get_recent(admin=Depends(verify_admin)):
    """Récupérer les 10 dernières alertes (pour le chargement initial)."""
    return get_recent_alerts(limit=10)


@router.get("/alerts/correlation")
def get_correlation(admin=Depends(verify_admin)):
    """Lancer une analyse de corrélation multi-sources à la demande."""
    return run_correlation()
