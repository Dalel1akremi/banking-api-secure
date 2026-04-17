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
    account_number: str = Field(..., pattern=r"^\d{10}$")
    alias: str = Field(..., min_length=2, max_length=100, 
                       description="Nom du titulaire servant d'alias (vérification CoP)")
    current_password: str
    otp_code: str

@router.get("/")
def get_beneficiaries(user=Depends(verify_token)):
    email = user["sub"]
    
    # Récupérer les bénéficiaires
    bens = list(beneficiaries_collection.find(
        {"owner_email": email},
        {"_id": 0}
    ))
    return bens

@router.post("/")
@limiter.limit("5/minute")
def add_beneficiary(request: Request, data: AddBeneficiary, user=Depends(verify_token)):
    email = user["sub"]

    # 1. Vérifier que le compte destinataire existe
    dest_acc = accounts_collection.find_one({"account_number": data.account_number})
    if not dest_acc:
        raise HTTPException(status_code=404, detail="Compte bénéficiaire introuvable.")

    # 2. ── CONFIRMATION OF PAYEE (CoP) via ALIAS ───────────────────────────
    # Récupérer le vrai titulaire du compte destinataire
    try:
        dest_owner = users_collection.find_one({"_id": bson.ObjectId(dest_acc["owner_id"])})
    except Exception:
        dest_owner = None

    if not dest_owner:
        raise HTTPException(status_code=404, detail="Titulaire du compte introuvable.")

    real_username  = (dest_owner.get("username", "") or "").strip().lower()
    real_lastname  = (dest_owner.get("lastname",  "") or "").strip().lower()
    real_fullname1 = f"{real_username} {real_lastname}"   # prénom nom
    real_fullname2 = f"{real_lastname} {real_username}"   # nom prénom
    
    # On utilise 'alias' comme nom à vérifier
    provided_alias = data.alias.strip().lower()

    if provided_alias not in (real_username, real_lastname, real_fullname1, real_fullname2):
        raise HTTPException(
            status_code=422,
            detail=(
                "❌ Confirmation of Payee échouée : "
                "le nom saisi (alias) ne correspond pas au titulaire réel du compte. "
                "Pour des raisons de sécurité, vous devez saisir le nom exact."
            )
        )
    # ────────────────────────────────────────────────────────────────────────

    # 3. Récupérer l'utilisateur courant
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # 4. Vérifier que l'utilisateur n'ajoute pas son propre compte
    if dest_acc["owner_id"] == str(db_user["_id"]):
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous ajouter comme bénéficiaire.")

    # 5. Vérifier le mot de passe
    if not check_password_hash(db_user.get("password", ""), data.current_password):
        raise HTTPException(status_code=403, detail="Mot de passe actuel incorrect.")

    # 6. Vérifier l'OTP
    verify_auth_otp(email, data.otp_code)

    # 7. Doublon ?
    exists = beneficiaries_collection.find_one({"owner_email": email, "account_number": data.account_number})
    if exists:
        raise HTTPException(status_code=400, detail="Ce bénéficiaire est déjà dans votre liste.")

    # 8. Enregistrement
    beneficiaries_collection.insert_one({
        "owner_email":      email,
        "account_number":   data.account_number,
        "alias":            data.alias, # Le nom vérifié sert d'alias
        "verified_name":    f"{dest_owner.get('username','')} {dest_owner.get('lastname','')}".strip(),
        "cop_verified":     True,
        "added_at":         datetime.utcnow()
    })

    return {"message": "Bénéficiaire ajouté avec succès (Identité vérifiée ✅)."}
