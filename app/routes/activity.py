from fastapi import APIRouter, Depends
from app.security.auth import verify_token
from app.db import activity_logs_collection

router = APIRouter(prefix="/activities", tags=["Activities"])

@router.get("/")
def get_activities(user = Depends(verify_token)):
    """
    Retourne la liste des activités (logs) pour l'utilisateur connecté.
    Les activités sont ordonnées de la plus récente à la plus ancienne.
    """
    user_id = str(user["id"])
    activities = list(activity_logs_collection.find(
        {"user_id": user_id},
        {"_id": 0} 
    ).sort("timestamp", -1))
    
    return activities
