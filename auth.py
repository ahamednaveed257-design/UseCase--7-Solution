import os
from functools import lru_cache

import httpx
import jwt
from fastapi import HTTPException

VALID_ROLES = {"Reader", "Knowledge Analyst", "Knowledge Manager", "Admin"}


@lru_cache(maxsize=4)
def get_jwks(jwks_url: str) -> dict:
    response = httpx.get(jwks_url, timeout=10)
    response.raise_for_status()
    return response.json()


def resolve_identity(authorization: str | None) -> str:
    issuer = os.getenv("KC_OIDC_ISSUER")
    audience = os.getenv("KC_OIDC_AUDIENCE")
    jwks_url = os.getenv("KC_OIDC_JWKS_URL")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="A bearer token is required.")
    if not issuer or not audience or not jwks_url:
        raise HTTPException(status_code=503, detail="OIDC identity is not configured.")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        signing_key = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Bearer token is invalid.") from exc

    for claim_name in ("roles", "role", "groups"):
        value = claims.get(claim_name)
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            roles = [role for role in value if role in VALID_ROLES]
            if roles:
                return roles[0]

    raise HTTPException(status_code=403, detail="No approved Knowledge Curator role is present.")
