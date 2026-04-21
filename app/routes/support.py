from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.security.auth import verify_token
from app.db import support_collection, users_collection
import datetime

router = APIRouter(prefix="/support", tags=["Support"])

# ==============================
# 📦 MODELS
# ==============================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)

class SupportMessageRequest(BaseModel):
    subject: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., pattern="^(Assurance|Credit|Incident Carte|Placement|Autre)$")
    content: str = Field(..., min_length=10, max_length=2000)

# ==============================
# 🤖 CHATBOT LOGIC (Simulation)
# ==============================

@router.post("/chat")
def chatbot_responder(data: ChatRequest, user=Depends(verify_token)):
    msg = data.message.lower()
    
    # Simple keyword-based logic (General Advice only as requested)
    if any(k in msg for k in ["bonjour", "salut", "hello"]):
        reply = "Bonjour ! Je suis votre assistant API Bank. Comment puis-je vous guider aujourd'hui ?"
    elif "solde" in msg:
        reply = "Pour consulter votre solde, rendez-vous sur votre 'Tableau de Bord'. Vous y verrez le solde actualisé de tous vos comptes."
    elif any(k in msg for k in ["bloquer", "opposition", "perdu", "vol"]):
        reply = "En cas de perte ou vol, allez dans 'Ma Carte' -> 'État de la carte' et cliquez sur 'Désactiver'. C'est instantané et sécurisé."
    elif "plafond" in msg:
        reply = "Les plafonds de paiement et retrait peuvent être modifiés dans la section 'Plafonds' de votre carte. Notez que cette option est réservée aux membres Prime."
    elif "prime" in msg:
        reply = "L'offre Prime (20 DT/an) vous permet de modifier vos plafonds, d'avoir des frais de renouvellement de carte gratuits et un design de carte exclusif."
    elif any(k in msg for k in ["conseiller", "messagerie", "contacter", "écrire"]):
        reply = "Pour une demande personnalisée, utilisez notre 'Messagerie Sécurisée' accessible depuis le menu Support. Un conseiller vous répondra sous 24h."
    else:
        reply = "Je ne suis pas sûr de comprendre. Vous pouvez me poser des questions sur votre solde, la sécurité de votre carte ou l'offre Prime. Sinon, contactez un conseiller via la messagerie."

    return {"reply": reply}

# ==============================
# 📩 SECURE MESSAGING
# ==============================

@router.post("/messages/send")
def send_support_message(data: SupportMessageRequest, user=Depends(verify_token)):
    user_id = str(user["id"])
    
    new_message = {
        "user_id": user_id,
        "subject": data.subject,
        "category": data.category,
        "content": data.content,
        "sender": "USER",
        "status": "SENT",
        "timestamp": datetime.datetime.utcnow(),
        "is_read": False
    }
    
    support_collection.insert_one(new_message)
    
    # Simulate an automated bank receipt (optional but nice)
    return {"message": "Message envoyé avec succès. Un conseiller l'étudiera rapidement."}

@router.get("/messages/history")
def get_message_history(user=Depends(verify_token)):
    user_id = str(user["id"])
    
    messages = list(support_collection.find(
        {"user_id": user_id}
    ).sort("timestamp", -1))
    
    for msg in messages:
        msg["id"] = str(msg["_id"])
        del msg["_id"]
        
    return messages
