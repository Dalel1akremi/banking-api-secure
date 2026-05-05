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
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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
    """
    # Récupérer le token
    token = credentials.credentials if credentials else None

    # Fallback : chercher dans les query params (pour SSE)
    if not token:
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(status_code=401, detail="Token manquant")

    # Essayer d'abord la validation Keycloak (RS256)
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") == "RS256":
            return verify_keycloak_token(token)
    except Exception:
        pass

    # Fallback : validation locale (HS256)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")