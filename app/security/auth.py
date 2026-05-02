from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# 🔐 Config
import os
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 🔐 Security
security = HTTPBearer(auto_error=False)

# 🔐 Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

# 🔐 Create JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 🔐 Verify JWT
from fastapi import Request

def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Try header first
    token = credentials.credentials if credentials else None
    
    # If no header, try query parameter (for SSE)
    if not token:
        token = request.query_params.get("token")
        print(f"DEBUG: Found token in query: {token[:10] if token else 'NONE'}...")
        
    if not token:
        print("DEBUG: Token missing in both header and query")
        raise HTTPException(status_code=401, detail="Token missing")
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"DEBUG: Token verified for: {payload.get('sub')}")
        return payload
    except JWTError as e:
        print(f"DEBUG: JWT Verification failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")