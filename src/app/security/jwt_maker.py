from passlib.context import CryptContext
import os
import jwt
from datetime import datetime, timezone, timedelta
from pathlib import Path

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ISS = os.getenv("JWT_ISS", "http://localhost:8000")
AUD = os.getenv("JWT_AUD", "api")
KID = os.getenv("JWT_KID", "k1")


def _read_key(env_name: str, default_filename: str) -> bytes:
    p = os.getenv(env_name)
    if not p:
        p = Path(__file__).parent / "keys" / default_filename
    p = Path(p)
    if not p.exists():
        raise RuntimeError("key_not_found")
    return p.read_bytes()


_PRIVATE_KEY_PEM = _read_key("JWT_PRIVATE_KEY_PATH", "jwt_private.pem")


def make_jwt_token(email):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISS,
        "aud": AUD,
        "sub": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(
        payload=payload,
        key=_PRIVATE_KEY_PEM,
        headers={"kid": KID},
        algorithm="RS256",
    )
