from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
from app.security.auth import verify_token
from app.db import budgets_collection, transactions_collection, accounts_collection
from app.rate_limiter import limiter
from datetime import datetime

router = APIRouter(prefix="/budgets", tags=["Budgets"])

# ─── Categories disponibles ───
CATEGORIES = ["alimentation", "transport", "logement", "sante", "loisirs", "shopping", "factures", "autres"]

class BudgetItem(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    category: str
    monthly_limit: float = Field(..., gt=0, le=100000)

class BudgetDelete(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10}$")
    category: str

@router.post("/")
@limiter.limit("10/minute")
def set_budget(request: Request, data: BudgetItem, user=Depends(verify_token)):
    """Crée ou met à jour un budget mensuel pour une catégorie."""
    if data.category not in CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Catégorie invalide. Options: {', '.join(CATEGORIES)}")

    # Vérifier que le compte appartient à l'utilisateur
    acc = accounts_collection.find_one({"account_number": data.account_number, "owner_id": str(user["id"])})
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable")

    budgets_collection.update_one(
        {"owner_id": str(user["id"]), "account_number": data.account_number, "category": data.category},
        {"$set": {
            "owner_id": str(user["id"]),
            "account_number": data.account_number,
            "category": data.category,
            "monthly_limit": data.monthly_limit,
            "updated_at": datetime.utcnow()
        }},
        upsert=True
    )
    return {"message": f"Budget '{data.category}' défini à {data.monthly_limit} DT/mois."}

@router.get("/{account_number}")
def get_budgets(account_number: str, user=Depends(verify_token)):
    """Récupère tous les budgets avec les dépenses actuelles du mois."""
    acc = accounts_collection.find_one({"account_number": account_number, "owner_id": str(user["id"])})
    if not acc:
        raise HTTPException(status_code=404, detail="Compte introuvable")

    # Période: début et fin du mois courant
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    # Récupérer tous les budgets définis
    budgets = list(budgets_collection.find(
        {"owner_id": str(user["id"]), "account_number": account_number},
        {"_id": 0}
    ))

    # Calculer les dépenses du mois pour chaque catégorie
    # Les types de transactions de dépense: withdraw, payment, bill_payment, transfer (sortant), service_fee
    outgoing_types = ["withdraw", "payment", "bill_payment", "phone_recharge", "service_fee"]

    all_txs = list(transactions_collection.find({
        "$or": [
            {"account_number": account_number, "type": {"$in": outgoing_types}},
            {"from_account": account_number, "type": "transfer"}
        ],
        "timestamp": {"$gte": month_start}
    }))

    # Mapper les transactions aux catégories budget
    # withdraw → transport/alimentation/autres
    # payment → shopping/loisirs/alimentation
    # bill_payment → factures/logement
    # transfer → autres
    # phone_recharge → factures
    # service_fee → autres

    tx_category_map = {
        "withdraw": "transport",
        "payment": "shopping",
        "bill_payment": "factures",
        "phone_recharge": "factures",
        "service_fee": "autres",
        "transfer": "autres"
    }

    # Calcul total par catégorie générique
    spent_by_category = {cat: 0.0 for cat in CATEGORIES}
    for tx in all_txs:
        # Priorité 1: Catégorie explicitement définie dans la transaction
        mapped_cat = tx.get("category")
        
        # Priorité 2: Mapping par défaut basé sur le type de transaction
        if not mapped_cat or mapped_cat not in CATEGORIES:
            tx_type = tx.get("type", "")
            mapped_cat = tx_category_map.get(tx_type, "autres")
            
        spent_by_category[mapped_cat] = round(spent_by_category.get(mapped_cat, 0.0) + tx.get("amount", 0.0), 2)

    # Enrichir les budgets avec les dépenses réelles et le statut d'alerte
    result = []
    for b in budgets:
        cat = b["category"]
        spent = spent_by_category.get(cat, 0.0)
        limit = b["monthly_limit"]
        pct = round((spent / limit) * 100, 1) if limit > 0 else 0
        result.append({
            "category": cat,
            "monthly_limit": limit,
            "spent": round(spent, 2),
            "remaining": round(max(0, limit - spent), 2),
            "percentage": min(pct, 100),
            "exceeded": spent > limit,
            "alert": pct >= 80
        })

    # Dépenses totales du mois (tous types confondus)
    total_spent = round(sum(tx.get("amount", 0) for tx in all_txs), 2)

    return {
        "account_number": account_number,
        "month": now.strftime("%B %Y"),
        "total_spent_this_month": total_spent,
        "budgets": result
    }

@router.delete("/")
@limiter.limit("10/minute")
def delete_budget(request: Request, data: BudgetDelete, user=Depends(verify_token)):
    """Supprime un budget mensuel."""
    result = budgets_collection.delete_one({
        "owner_id": str(user["id"]),
        "account_number": data.account_number,
        "category": data.category
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Budget introuvable")
    return {"message": f"Budget '{data.category}' supprimé."}
