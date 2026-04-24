from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from app.db import beneficiaries_collection, accounts_collection, users_collection
from app.rate_limiter import limiter
from app.security.auth import verify_token
from app.routes.user import verify_auth_otp
from werkzeug.security import check_password_hash
from datetime import datetime
import bson

router = APIRouter(prefix="/beneficiaries", tags=["Beneficiaries"])

class AddBeneficiary(BaseModel):
    account_number: str = Field(..., pattern=r"^\d{10,20}$") # 10 chiffres internes ou jusqu'à 20 (RIB)
    alias: str = Field(..., min_length=2, max_length=100)
    current_password: str
    otp_code: str

@router.get("/")
def get_beneficiaries(user=Depends(verify_token)):
    email = user["sub"]
    bens = list(beneficiaries_collection.find({"owner_email": email}, {"_id": 0}))
    return bens

@router.post("/")
@limiter.limit("5/minute")
def add_beneficiary(request: Request, data: AddBeneficiary, user=Depends(verify_token)):
    email = user["sub"]
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # 1. Vérifier le mot de passe et l'OTP d'abord
    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")
    verify_auth_otp(email, data.otp_code)

    # 2. Vérifier si c'est un compte interne
    dest_acc = accounts_collection.find_one({"account_number": data.account_number})
    
    is_external = False
    verified_name = None
    cop_verified = False

    if dest_acc:
        # LOGIQUE COMPTE INTERNE (CoP ACTIVE)
        if dest_acc["owner_id"] == str(db_user["_id"]):
            raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous ajouter comme bénéficiaire.")

        try:
            dest_owner = users_collection.find_one({"_id": bson.ObjectId(dest_acc["owner_id"])})
        except Exception:
            dest_owner = None

        if dest_owner:
            real_username  = (dest_owner.get("username", "") or "").strip().lower()
            real_lastname  = (dest_owner.get("lastname",  "") or "").strip().lower()
            real_fullname1 = f"{real_username} {real_lastname}"
            real_fullname2 = f"{real_lastname} {real_username}"
            provided_alias = data.alias.strip().lower()

            if provided_alias in (real_username, real_lastname, real_fullname1, real_fullname2):
                verified_name = f"{dest_owner.get('username','')} {dest_owner.get('lastname','')}".strip()
                cop_verified = True
            else:
                raise HTTPException(
                    status_code=422,
                    detail="❌ CoP échouée : le nom ne correspond pas au titulaire du compte interne."
                )
    else:
        # LOGIQUE COMPTE EXTERNE
        is_external = True
        verified_name = "Banque Externe (Identité non vérifiable)"
        cop_verified = False

    # 3. Doublon ?
    exists = beneficiaries_collection.find_one({"owner_email": email, "account_number": data.account_number})
    if exists:
        raise HTTPException(status_code=400, detail="Ce bénéficiaire est déjà dans votre liste.")

    # 4. Enregistrement
    beneficiaries_collection.insert_one({
        "owner_email":      email,
        "account_number":   data.account_number,
        "alias":            data.alias,
        "verified_name":    verified_name,
        "cop_verified":     cop_verified,
        "is_external":      is_external,
        "added_at":         datetime.utcnow()
    })

    msg = "Bénéficiaire interne ajouté (Vérifié ✅)" if not is_external else "Bénéficiaire externe ajouté (Non vérifié ⚠️)"
    return {"message": msg}
