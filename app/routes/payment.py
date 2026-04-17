from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.security.auth import verify_token
from app.rate_limiter import limiter
router = APIRouter(prefix="/payments", tags=["Payments"])

# ✅ modèle pour le body
class Payment(BaseModel):
    receiver: str
    amount: float

@router.post("/")
@limiter.limit("10/minute")
def make_payment(request: Request, payment: Payment, user=Depends(verify_token)):
    sender = user["sub"]  
    return {
        "message": "Payment processed",
        "from": sender,
        "to": payment.receiver,
        "amount": payment.amount,
    }