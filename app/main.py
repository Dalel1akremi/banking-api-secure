from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import logging
import time

# --- Setup Logger ---
logging.basicConfig(
    filename="security_audit.log",
    level=logging.INFO,
    format="[%(asctime)s] | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("audit_logger")

from app.routes import account, payment, auth, user, email_verification, beneficiary, activity, support, admin, locations, budget, financial_hub, alerts
from app.rate_limiter import limiter
from fastapi.middleware.cors import CORSMiddleware

from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from app.security.auth import verify_token
from fastapi import Depends

app = FastAPI(
    title="Banking API Secure", 
    root_path="/api",
    docs_url=None, 
    redoc_url=None, 
    openapi_url=None
)

@app.get("/docs", include_in_schema=False)
async def get_swagger_ui(request: Request, user=Depends(verify_token)):
    token = request.query_params.get("token")
    return get_swagger_ui_html(
        openapi_url=f"/api/openapi.json?token={token}" if token else "/api/openapi.json", 
        title=app.title + " - Swagger UI"
    )

@app.get("/redoc", include_in_schema=False)
async def get_redoc(request: Request, user=Depends(verify_token)):
    token = request.query_params.get("token")
    return get_redoc_html(
        openapi_url=f"/api/openapi.json?token={token}" if token else "/api/openapi.json", 
        title=app.title + " - ReDoc"
    )

@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(user=Depends(verify_token)):
    return get_openapi(
        title=app.title, 
        version="1.0.0", 
        routes=app.routes
    )

# Start threat monitor background thread
from app.utils.threat_monitor import start_monitor

@app.on_event("startup")
async def on_startup():
    start_monitor()

# Security: CORS Policy (Only frontend is allowed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.utils.security_state import is_ip_blocked
from fastapi.responses import JSONResponse

# --- Middlewares (Audit Logging & Security Headers) ---
@app.middleware("http")
async def combined_security_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Get Real Client IP (Robust check)
    client_ip = request.headers.get("X-Real-IP") or \
                request.headers.get("X-Forwarded-For", "").split(',')[0] or \
                (request.client.host if request.client else "Unknown IP")
                
    # --- FIREWALL APPLICATIF : Blocage IP ---
    if is_ip_blocked(client_ip):
        return JSONResponse(
            status_code=403, 
            content={"detail": "Votre IP est actuellement bloquée. Veuillez contacter notre agence pour voir le problème."}
        )
    
    # --- FIREWALL APPLICATIF : Détection XSS (OWASP A03) ---
    import re
    query_str = str(request.query_params)
    if re.search(r"<\s*script|javascript:|onerror\s*=|onload\s*=", query_str, re.IGNORECASE):
        logger.warning(f"SECURITY_ALERT | XSS_BLOCKED_API | IP: {client_ip} | PATH: {request.url.path}")
        return JSONResponse(
            status_code=400,
            content={"detail": "⛔ Tentative d'injection XSS détectée et bloquée par l'API."}
        )
    
    # Pass the request down the chain
    response = await call_next(request)
    
    # Inject Security Headers (OWASP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Calculate duration
    process_time_ms = round((time.time() - start_time) * 1000, 2)
    
    method = request.method
    path = request.url.path
    status = response.status_code
    
    target_email = getattr(request.state, "target_email", None)
    if not target_email:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                from jose import jwt
                claims = jwt.get_unverified_claims(token)
                target_email = claims.get("sub") or claims.get("email") or claims.get("preferred_username")
                request.state.target_email = target_email
            except Exception:
                pass

    email_suffix = f" | TARGET_EMAIL: {target_email}" if target_email else ""
    
    log_message = f"IP: {client_ip} | METHOD: {method} | PATH: {path} | STATUS: {status} | DURATION: {process_time_ms}ms{email_suffix}"
    
    # Colorize errors vs success logically in log level
    if status >= 400:
        logger.warning(log_message)
    else:
        logger.info(log_message)
        
    return response

def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    # Récupérer l'email de la requête
    email = getattr(request.state, "target_email", None)
    if not email:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                from jose import jwt
                claims = jwt.get_unverified_claims(token)
                email = claims.get("sub") or claims.get("email") or claims.get("preferred_username")
                request.state.target_email = email
            except Exception:
                pass

    # ✅ Bloquer le compte utilisateur en DB jusqu'à déblocage par l'administrateur
    if email:
        try:
            from app.db import users_collection
            u = users_collection.find_one({"email": email})
            if u and not u.get("is_admin"):
                users_collection.update_one(
                    {"email": email},
                    {"$set": {
                        "status": "blocked",
                        "block_reason": "Dépassement du quota de requêtes (Rate Limit)"
                    }}
                )
                print(f"[RateLimit] Compte bloqué en base: {email}")
        except Exception as e:
            print(f"[RateLimit] Erreur blocage compte: {e}")

    return JSONResponse(
        status_code=429,
        content={"detail": "Quota de requêtes dépassé. Votre compte est bloqué. Contactez l'administrateur pour le débloquer."}
    )

# Setup Rate Limiting Exception Handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    try:
        if isinstance(exc.body, dict) and "email" in exc.body:
            request.state.target_email = exc.body.get("email")
        elif isinstance(exc.body, bytes):
            import json
            body_dict = json.loads(exc.body.decode())
            if "email" in body_dict:
                request.state.target_email = body_dict.get("email")
    except:
        pass
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

from slowapi.middleware import SlowAPIMiddleware
app.add_middleware(SlowAPIMiddleware)

# routes
app.include_router(user.router)
app.include_router(email_verification.router)
app.include_router(account.router)
app.include_router(payment.router)
app.include_router(auth.router)
app.include_router(beneficiary.router)
app.include_router(activity.router)
app.include_router(support.router)
app.include_router(admin.router)
app.include_router(locations.router)
app.include_router(budget.router)
app.include_router(financial_hub.router)
app.include_router(alerts.router)

@app.get("/")
def root():
    return {"message": "Secure Banking API is running"}