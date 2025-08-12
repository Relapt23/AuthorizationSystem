import os
import json
from fastapi import APIRouter, Response
from jwcrypto import jwk

router = APIRouter()


def _load_public_jwk() -> dict:
    pub_path = os.getenv("JWT_PUBLIC_KEY_PATH")
    with open(pub_path, "rb") as f:
        key = jwk.JWK.from_pem(f.read())
    data = json.loads(key.export(private_key=False))
    data.update({"use": "sig", "alg": "RS256", "kid": os.getenv("JWT_KID", "k1")})
    return {"keys": [data]}


_JWKS = _load_public_jwk()


@router.get("/.well-known/jwks.json")
def jwks():
    return Response(
        content=json.dumps(_JWKS),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )
