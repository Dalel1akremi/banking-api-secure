from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.security.auth import verify_token
from app.db import appointments_collection, budgets_collection, accounts_collection, transactions_collection, users_collection
import datetime
from bson import ObjectId
import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash')
else:
    gemini_model = None

router = APIRouter(prefix="/financial-hub", tags=["Financial Hub"])

# ==============================
# 📦 MODELS
# ==============================

class AppointmentCreate(BaseModel):
    subject: str = Field(..., min_length=2, max_length=100)
    advisor_name: str = Field(..., min_length=2, max_length=100)
    appointment_date: str  # Format: YYYY-MM-DD
    appointment_time: str  # Format: HH:MM
    notes: str = Field("", max_length=500)

# ==============================
# 🤖 AI ADVICE LOGIC
# ==============================

@router.get("/advice/{account_number}")
def get_financial_advice(account_number: str, user=Depends(verify_token)):
    user_id = str(user["id"])
    
    # 1. Fetch budgets for the user
    budgets = list(budgets_collection.find({"user_id": user_id}))
    
    # 2. Fetch recent spending for the account (simulated or real from budget logic)
    # We'll use the same logic as in budget.py to get current month totals
    now = datetime.datetime.utcnow()
    start_of_month = datetime.datetime(now.year, now.month, 1).isoformat()
    
    txs = list(transactions_collection.find({
        "$or": [{"from_account": account_number}, {"to_account": account_number}],
        "timestamp": {"$gte": start_of_month}
    }))
    
    # Simple aggregation for the prompt
    spending_summary = {}
    for tx in txs:
        cat = tx.get("category", "Autres")
        amt = float(tx.get("amount", 0))
        if tx.get("from_account") == account_number: # It's an expense
            spending_summary[cat] = spending_summary.get(cat, 0) + amt

    # 3. Prepare the prompt for Gemini
    budget_info = []
    for b in budgets:
        cat = b["category"]
        limit = b["monthly_limit"]
        spent = spending_summary.get(cat, 0)
        budget_info.append(f"- {cat}: Limite {limit} DT, Dépensé {spent:.2f} DT")

    prompt = (
        "En tant qu'expert financier pour API Bank, analyse la situation budgétaire suivante de l'utilisateur "
        "pour le mois en cours et donne 3 conseils personnalisés, courts et percutants en français. "
        "Utilise un ton premium, encourageant et professionnel.\n\n"
        "Résumé des budgets :\n" + "\n".join(budget_info) + "\n\n"
        "Si aucun budget n'est défini, donne des conseils généraux sur l'épargne et l'investissement."
        "Formatte ta réponse en une liste de points avec des titres courts."
    )

    advice = []
    if gemini_model:
        try:
            response = gemini_model.generate_content(prompt)
            # Simple parsing of the response text into a list
            lines = response.text.strip().split('\n')
            current_tip = ""
            for line in lines:
                if line.strip().startswith(('*', '-', '1.', '2.', '3.')):
                    if current_tip: advice.append(current_tip.strip())
                    current_tip = line.strip().lstrip('* -123.').strip()
                else:
                    current_tip += " " + line.strip()
            if current_tip: advice.append(current_tip.strip())
        except Exception as e:
            print(f"Gemini Error: {e}")
            advice = [
                "Diversifiez votre épargne : Envisagez de placer 10% de vos revenus dans un compte d'épargne à terme.",
                "Suivi régulier : Consultez votre historique chaque semaine pour mieux maîtriser vos dépenses imprévues.",
                "Optimisation fiscale : Renseignez-vous sur les produits d'épargne exonérés d'impôts."
            ]
    else:
        advice = [
            "Épargne de précaution : Il est recommandé de garder 3 à 6 mois de dépenses sur un compte accessible.",
            "Règle du 50/30/20 : Allouez 50% aux besoins, 30% aux envies et 20% à l'épargne.",
            "Objectifs clairs : Définissez un projet (voyage, achat) pour donner du sens à vos économies."
        ]

    return {"advice": advice[:3]} # Return top 3 tips

# ==============================
# 📅 APPOINTMENT BOOKING
# ==============================

@router.post("/appointments")
def book_appointment(data: AppointmentCreate, user=Depends(verify_token)):
    user_id = str(user["id"])
    
    new_appt = {
        "user_id": user_id,
        "subject": data.subject,
        "advisor_name": data.advisor_name,
        "date": data.appointment_date,
        "time": data.appointment_time,
        "notes": data.notes,
        "status": "CONFIRMED",
        "created_at": datetime.datetime.utcnow()
    }
    
    result = appointments_collection.insert_one(new_appt)
    return {"message": "Rendez-vous confirmé !", "id": str(result.inserted_id)}

@router.get("/appointments")
def get_appointments(user=Depends(verify_token)):
    user_id = str(user["id"])
    appts = list(appointments_collection.find({"user_id": user_id}).sort("date", 1))
    
    for a in appts:
        a["id"] = str(a["_id"])
        del a["_id"]
    return appts

@router.get("/admin/appointments")
def get_all_appointments(user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
        
    appts = list(appointments_collection.find().sort("date", 1))
    for a in appts:
        a["id"] = str(a["_id"])
        del a["_id"]
        # Fetch user name for admin context
        u = users_collection.find_one({"_id": ObjectId(a["user_id"])})
        if u:
            a["user_name"] = f"{u['username']} {u['lastname']}"
        else:
            a["user_name"] = "Utilisateur inconnu"
            
    return appts

@router.post("/admin/appointments/status/{appt_id}")
def update_appointment_status(appt_id: str, status: str, user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
        
    result = appointments_collection.update_one(
        {"_id": ObjectId(appt_id)},
        {"$set": {"status": status.upper()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Rendez-vous non trouvé.")
    return {"message": f"Statut mis à jour : {status}"}

@router.put("/admin/appointments/reschedule/{appt_id}")
def reschedule_appointment(appt_id: str, date: str, time: str, user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
        
    result = appointments_collection.update_one(
        {"_id": ObjectId(appt_id)},
        {"$set": {"date": date, "time": time, "status": "RESCHEDULED"}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Rendez-vous non trouvé.")
    return {"message": "Rendez-vous replanifié."}

@router.delete("/appointments/{appt_id}")
def cancel_appointment(appt_id: str, user=Depends(verify_token)):
    user_id = str(user["id"])
    result = appointments_collection.delete_one({"_id": ObjectId(appt_id), "user_id": user_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rendez-vous non trouvé.")
    
    return {"message": "Rendez-vous annulé."}
