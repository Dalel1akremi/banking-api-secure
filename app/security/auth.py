from datetime import datetime, timedelta
from jose import jwt, JWTError, jwk
from jose.utils import base64url_decode
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import requests
import json
import logging

logger = logging.getLogger("audit_logger")

# =============================================================
# 🔐 Configuration locale (conservée pour la compatibilité)
# =============================================================
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 heures — assez long pour une session utilisateur normale


# =============================================================
# 🔐 Configuration Keycloak (OAuth2 / OpenID Connect)
# =============================================================
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080/auth")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "banking-realm")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "banking-api")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")

# URL des clés publiques de Keycloak (JWKS = JSON Web Key Set)
KEYCLOAK_JWKS_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"

# Cache des clés publiques (pour ne pas appeler Keycloak à chaque requête)
_jwks_cache = None

# =============================================================
# 🔐 Security
# =============================================================
security = HTTPBearer(auto_error=False)

# 🔐 Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

# =============================================================
# 🔐 Gestion des clés publiques Keycloak (JWKS)
# =============================================================
def get_keycloak_public_keys():
    """Récupère et met en cache les clés publiques de Keycloak."""
    global _jwks_cache
    if _jwks_cache:
        return _jwks_cache
    try:
        response = requests.get(KEYCLOAK_JWKS_URL, timeout=5)
        response.raise_for_status()
        _jwks_cache = response.json()
        logger.info(f"✅ Clés JWKS Keycloak chargées depuis {KEYCLOAK_JWKS_URL}")
        return _jwks_cache
    except Exception as e:
        logger.warning(f"⚠️ Keycloak JWKS non disponible: {e}")
        return None

def verify_keycloak_token(token: str) -> dict:
    """Valide un token JWT émis par Keycloak."""
    jwks = get_keycloak_public_keys()
    if not jwks:
        raise HTTPException(status_code=503, detail="Service d'identité Keycloak non disponible")

    try:
        # Décoder le header du token pour obtenir le kid (key ID)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Trouver la bonne clé publique dans le JWKS
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "n": key["n"],
                    "e": key["e"],
                }
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Clé publique Keycloak introuvable")

        # Valider le token avec la clé publique
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=KEYCLOAK_CLIENT_ID,
            issuer=KEYCLOAK_ISSUER,
            options={"verify_aud": False}  # Keycloak met l'audience différemment selon la config
        )
        logger.info(f"✅ Token Keycloak valide pour: {payload.get('preferred_username', payload.get('sub'))}")
        return payload

    except JWTError as e:
        logger.warning(f"⚠️ Token Keycloak invalide: {e}")
        raise HTTPException(status_code=401, detail=f"Token Keycloak invalide: {str(e)}")

# =============================================================
# 🔐 Création/Vérification des tokens locaux (conservés)
# =============================================================
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Vérification hybride : accepte les tokens Keycloak (RS256) ET les tokens locaux (HS256).
    Tente Keycloak en premier, puis fallback sur le système local.
    Assure également la présence de l'ID MongoDB interne ('id') dans le payload.
    """
    # Récupérer le token
    token = credentials.credentials if credentials else None

    # Fallback : chercher dans les query params (pour SSE)
    if not token:
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(status_code=401, detail="Token manquant")

    payload = None

    # 1. Essayer d'abord la validation Keycloak (RS256)
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") == "RS256":
            payload = verify_keycloak_token(token)
    except Exception:
        pass

    # 2. Fallback : validation locale (HS256)
    if not payload:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise HTTPException(status_code=401, detail="Token invalide ou expiré")

    # 3. Réconciliation : Assurer la présence de l'ID MongoDB interne
    # Indispensable pour lier le token Keycloak à la collection 'accounts' locale
    if payload and "id" not in payload:
        # On utilise l'email comme pivot (présent dans 'sub', 'email' ou 'preferred_username')
        email = payload.get("email") or payload.get("preferred_username") or payload.get("sub")
        if email:
            from app.db import users_collection # Import tardif pour éviter les dépendances circulaires
            db_user = users_collection.find_one({"email": email})
            if db_user:
                payload["id"] = str(db_user["_id"])
                # Synchroniser aussi le statut admin si absent
                if "is_admin" not in payload:
                    payload["is_admin"] = db_user.get("is_admin", False)
            else:
                # Si l'utilisateur Keycloak n'existe pas encore dans notre MongoDB
                # on pourrait lever une erreur ou le créer à la volée. 
                # Pour l'instant, on laisse passer mais l'ID restera manquant.
                pass

    return payload

# =============================================================
# 🔐 Validation des Scopes (Open Banking)
# =============================================================
def require_scope(required_scope: str):
    """
    Dépendance pour vérifier si le token possède un scope ou un rôle spécifique.
    """
    def scope_verifier(payload: dict = Depends(verify_token)):
        # Keycloak met les scopes dans "scope" (chaîne séparée par des espaces)
        # et les rôles dans "realm_access/roles" (liste)
        token_scopes = payload.get("scope", "").split()
        token_roles = payload.get("realm_access", {}).get("roles", [])
        
        # On accepte aussi les scopes définis localement pour le fallback HS256
        local_scopes = payload.get("scopes", [])
        
        # --- AJOUT : Scopes par défaut pour les utilisateurs authentifiés ---
        # Si l'utilisateur est authentifié, on lui donne les accès de base
        default_scopes = ["read:accounts", "write:accounts", "read:profile"]
        
        all_perms = set(token_scopes + token_roles + local_scopes + default_scopes)
        
        if required_scope not in all_perms:
            logger.warning(f"⛔ Accès refusé : Scope '{required_scope}' manquant pour l'utilisateur {payload.get('sub')}")
            raise HTTPException(
                status_code=403, 
                detail=f"Action interdite : vous n'avez pas le droit '{required_scope}'"
            )
        return payload
    return scope_verifier