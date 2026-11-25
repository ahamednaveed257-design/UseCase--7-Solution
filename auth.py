import os
import httpx
import jwt
from fastapi import HTTPException

VALID_ROLES = {"Reader", "Knowledge Analyst", "Knowledge Manager", "Admin"}


def resolve_identity(authorization: str | None) -> tuple[str, set[str]]:
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
    except (httpx.HTTPError, jwt.PyJWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Bearer token is invalid.") from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(status_code=401, detail="Bearer token has no subject.")

    roles: set[str] = set()
    for claim_name in ("roles", "role", "groups"):
        value = claims.get(claim_name)
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            roles.update(role for role in value if isinstance(role, str) and role in VALID_ROLES)

    if not roles:
        raise HTTPException(status_code=403, detail="No approved Knowledge Curator role is present.")
    return subject, roles
