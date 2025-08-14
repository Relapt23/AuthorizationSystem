import os
import json
from fastapi import APIRouter, Response
from jwcrypto import jwk
from pathlib import Path

router = APIRouter()

KID = os.getenv("JWT_KID", "k1")


def _read_key(env_name: str, default_filename: str) -> bytes:
    p = os.getenv(env_name)
    if not p:
        p = Path(__file__).parent / "keys" / default_filename
    p = Path(p)
    if not p.exists():
        raise RuntimeError("key_not_found")
    return p.read_bytes()


def _build_jwks(pub_pem: bytes) -> dict:
    key = jwk.JWK.from_pem(pub_pem)
    data = json.loads(key.export(private_key=False))
    data.update({"use": "sig", "alg": "RS256", "kid": KID})
    return {"keys": [data]}


try:
    _PUBLIC_KEY_PEM = _read_key("JWT_PUBLIC_KEY_PATH", "jwt_public.pem")
    _JWKS = _build_jwks(_PUBLIC_KEY_PEM)
except RuntimeError:
    _PUBLIC_KEY_PEM = None
    _JWKS = None


@router.get("/.well-known/jwks.json")
def jwks():
    return Response(
        content=json.dumps(_JWKS),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )
