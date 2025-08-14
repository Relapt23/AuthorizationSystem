import jwt
from fastapi import APIRouter, Request

JWKS_URL = "http://authorization_app_example:8000/.well-known/jwks.json"
ISS = "http://authorization_app_example:8000"

_jwk_client = jwt.PyJWKClient(JWKS_URL, cache_keys=True)

app = APIRouter()


def verify(bearer: str) -> dict:
    token = bearer.split(" ", 1)[1]
    key = _jwk_client.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience="api",
        issuer=ISS,
        options={"require": ["exp", "iat", "iss", "aud", "sub"], "leeway": 60},
    )


@app.get("/hello")
async def check_hello(request: Request):
    bearer = request.headers["Authorization"]
    res = verify(bearer)
    return "Hello, " + res["sub"]
