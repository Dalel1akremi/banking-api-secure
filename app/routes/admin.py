from fastapi import APIRouter, Depends, HTTPException
from app.security.auth import verify_token
from app.db import users_collection, accounts_collection, transactions_collection, support_collection, activity_logs_collection
from bson import ObjectId

router = APIRouter(prefix="/admin", tags=["Admin"])

def verify_admin(user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accès refusé. Privilèges administrateur requis.")
    return user

@router.get("/stats")
def get_dashboard_stats(admin=Depends(verify_admin)):
    total_users = users_collection.count_documents({})
    total_accounts = accounts_collection.count_documents({})
    total_transactions = transactions_collection.count_documents({})
    
    # Calculate total volume of transactions
    pipeline = [{"$group": {"_id": None, "total_volume": {"$sum": "$amount"}}}]
    volume_result = list(transactions_collection.aggregate(pipeline))
    total_volume = volume_result[0]["total_volume"] if volume_result else 0
    
    return {
        "total_users": total_users,
        "total_accounts": total_accounts,
        "total_transactions": total_transactions,
        "total_volume": total_volume
    }

@router.get("/activities")
def get_global_activities(admin=Depends(verify_admin)):
    activities = list(activity_logs_collection.find().sort("timestamp", -1).limit(50))
    for act in activities:
        act["_id"] = str(act["_id"])
    return activities

@router.get("/messages")
def get_all_messages(admin=Depends(verify_admin)):
    messages = list(support_collection.find().sort("timestamp", -1))
    for msg in messages:
        msg["id"] = str(msg["_id"])
        del msg["_id"]
    return messages

@router.put("/messages/{msg_id}/resolve")
def resolve_message(msg_id: str, admin=Depends(verify_admin)):
    try:
        obj_id = ObjectId(msg_id)
    except Exception:
        raise HTTPException(status_code=400, detail="ID Invalide")
        
    result = support_collection.update_one(
        {"_id": obj_id},
        {"$set": {"status": "RESOLVED"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Message introuvable")
    return {"message": "Message marqué comme résolu."}
