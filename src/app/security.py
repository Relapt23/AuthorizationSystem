from passlib.context import CryptContext
import os
import jwt
from datetime import datetime, timezone, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


def make_jwt_token(username):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": username, "exp": int((now + timedelta(minutes=15)).timestamp())},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
