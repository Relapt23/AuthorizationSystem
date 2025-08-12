from passlib.context import CryptContext
import os
import jwt
from datetime import datetime, timezone, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


with open(os.getenv("JWT_PRIVATE_KEY_PATH"), "rb") as f:
    _PRIVATE_KEY = f.read()


def make_jwt_token(username):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": os.getenv("JWT_ISS", "http://localhost"),
        "aud": os.getenv("JWT_AUD", "api"),
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(
        payload=payload,
        key=_PRIVATE_KEY,
        headers={"kid": os.getenv("JWT_KID", "k1")},
        algorithm="RS256",
    )
