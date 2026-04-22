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

from app.routes import account, payment, auth, user, email_verification, beneficiary, activity, support, admin
from app.rate_limiter import limiter
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Banking API Secure")

# Security: CORS Policy (Only frontend is allowed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Middlewares (Audit Logging & Security Headers) ---
@app.middleware("http")
async def combined_security_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Pass the request down the chain
    response = await call_next(request)
    
    # Inject Security Headers (OWASP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Calculate duration
    process_time_ms = round((time.time() - start_time) * 1000, 2)
    client_ip = request.client.host if request.client else "Unknown IP"
    method = request.method
    path = request.url.path
    status = response.status_code
    
    log_message = f"IP: {client_ip} | METHOD: {method} | PATH: {path} | STATUS: {status} | DURATION: {process_time_ms}ms"
    
    # Colorize errors vs success logically in log level
    if status >= 400:
        logger.warning(log_message)
    else:
        logger.info(log_message)
        
    return response

# Setup Rate Limiting Exception Handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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

@app.get("/")
def root():
    return {"message": "Secure Banking API is running"}