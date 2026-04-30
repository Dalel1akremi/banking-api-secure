from app.routes.email_verification import send_admin_action_email
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
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


# ==========================================
# GESTION DES UTILISATEURS
# ==========================================

@router.get("/users")
def get_all_users(admin=Depends(verify_admin)):
    users = list(users_collection.find({}, {"password_hash": 0, "biometric_credential_id": 0}).sort("created_at", -1))
    for u in users:
        u["id"] = str(u["_id"])
        del u["_id"]
    return users

from pydantic import BaseModel
class StatusUpdate(BaseModel):
    status: str
    otp_code: str = None
    reason: str = 'Action administrative standard'


@router.get("/users/{user_id}")
def get_user_details(user_id: str, admin=Depends(verify_admin)):
    try:
        obj_id = ObjectId(user_id)
    except:
        raise HTTPException(status_code=400, detail="ID Invalide")
        
    user = users_collection.find_one({"_id": obj_id}, {"password_hash": 0, "biometric_credential_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        
    user["id"] = str(user["_id"])
    del user["_id"]
    
    accounts = list(accounts_collection.find({"owner_id": user_id}))
    account_numbers = []
    for a in accounts:
        a["id"] = str(a["_id"])
        del a["_id"]
        account_numbers.append(a.get("account_number"))
        
    # Fetch transactions for these accounts
    transactions = []
    if account_numbers:
        txs = list(transactions_collection.find({
            "$or": [
                {"from_account": {"$in": account_numbers}},
                {"to_account": {"$in": account_numbers}},
                {"account_number": {"$in": account_numbers}}
            ]
        }).sort("timestamp", -1).limit(200))
        for tx in txs:
            tx["id"] = str(tx["_id"])
            del tx["_id"]
            transactions.append(tx)
            
    return {"user": user, "accounts": accounts, "transactions": transactions}

@router.put("/users/{user_id}/status")

def update_user_status(user_id: str, data: StatusUpdate, background_tasks: BackgroundTasks, admin=Depends(verify_admin)):
    try:
        obj_id = ObjectId(user_id)
    except:
        raise HTTPException(status_code=400, detail="ID Invalide")
        
    # ✅ 2FA Verification for Admin
    if not data.otp_code:
        raise HTTPException(status_code=400, detail="Code OTP requis pour cette action")
    
    # Simple OTP check logic (duplicated for modularity or we could import it)
    from app.db import otp_collection
    otp = otp_collection.find_one({"email": admin["sub"], "code": data.otp_code})
    if not otp:
        raise HTTPException(status_code=400, detail="Code OTP invalide")
    otp_collection.delete_one({"_id": otp["_id"]})

    result = users_collection.update_one(
        {"_id": obj_id},
        {"$set": {"status": data.status}}
    )
    # Send Notification Email
    target_user = users_collection.find_one({"_id": obj_id})
    admin_user = users_collection.find_one({"email": admin["sub"]})
    if target_user and admin_user:
        background_tasks.add_task(
            send_admin_action_email,
            target_user["email"],
            f"{target_user.get('username', '')} {target_user.get('lastname', '')}",
            data.status, data.reason,
            {
                "name": admin_user.get("username", "Admin"),
                "lastname": admin_user.get("lastname", ""),
                "email": admin_user.get("email", "")
            }
        )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return {"message": f"Statut mis à jour : {data.status}"}

# ==========================================
# GESTION DES COMPTES
# ==========================================

@router.get("/accounts")
def get_all_accounts(admin=Depends(verify_admin)):
    accounts = list(accounts_collection.find().sort("created_at", -1))
    for a in accounts:
        a["id"] = str(a["_id"])
        del a["_id"]
        # Attach user info if possible (optional)
        user = users_collection.find_one({"_id": ObjectId(a["owner_id"])}, {"username": 1, "lastname": 1, "email": 1})
        if user:
            a["owner_name"] = f"{user.get('username', '')} {user.get('lastname', '')}"
            a["owner_email"] = user.get("email", "")
    return accounts

@router.put("/accounts/{account_number}/status")
def update_account_status(account_number: str, data: StatusUpdate, background_tasks: BackgroundTasks, admin=Depends(verify_admin)):
    # ✅ 2FA Verification for Admin
    if not data.otp_code:
        raise HTTPException(status_code=400, detail="Code OTP requis pour cette action")
    
    from app.db import otp_collection
    otp = otp_collection.find_one({"email": admin["sub"], "code": data.otp_code})
    if not otp:
        raise HTTPException(status_code=400, detail="Code OTP invalide")
    otp_collection.delete_one({"_id": otp["_id"]})

    result = accounts_collection.update_one(
        {"account_number": account_number},
        {"$set": {"card_status": data.status}}
    )
    # Send Notification Email
    acc = accounts_collection.find_one({"account_number": account_number})
    admin_user = users_collection.find_one({"email": admin["sub"]})
    if acc and admin_user:
        target_user = users_collection.find_one({"_id": ObjectId(acc["owner_id"])})
        if target_user:
            background_tasks.add_task(
                send_admin_action_email,
                target_user["email"],
                f"{target_user.get('username', '')} {target_user.get('lastname', '')}",
                data.status, data.reason,
                {
                    "name": admin_user.get("username", "Admin"),
                    "lastname": admin_user.get("lastname", ""),
                    "email": admin_user.get("email", "")
                }
            )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Compte introuvable")
    return {"message": f"Statut du compte mis à jour : {data.status}"}

# ==========================================
# REGISTRE DES TRANSACTIONS (LEDGER)
# ==========================================

@router.get("/transactions")
def get_all_transactions(admin=Depends(verify_admin)):
    transactions = list(transactions_collection.find().sort("timestamp", -1).limit(500))
    for tx in transactions:
        tx["id"] = str(tx["_id"])
        del tx["_id"]
    return transactions
