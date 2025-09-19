from datetime import datetime, timedelta, timezone
from typing import Any
import jwt
from passlib.context import CryptContext
from app.core.config import settings  # import the Settings singleton

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🔑 Load RSA keys from paths in settings
with open(settings.PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

with open(settings.PUBLIC_KEY_PATH, "r") as f:
    PUBLIC_KEY = f.read()

ALGORITHM = "RS256"


def create_access_token(subject: str | Any, expires_delta: timedelta | None = None) -> str:
    # Use token expiry from settings if not passed explicitly
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """Verify JWT using the public key"""
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
