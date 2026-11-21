import os
from typing import Optional
import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException, status
from src.models import User

class JWTAuthenticator:
    """Verifies asymmetric JWTs using a local air-gapped PEM public key or an OIDC JWKS URL."""

    def __init__(self):
        self.algorithm = os.getenv("JWT_ALGORITHM", "RS256")
        self.issuer = os.getenv("JWT_ISSUER", "https://defense.internal")
        self.audience = os.getenv("JWT_AUDIENCE", "defense-llm-proxy")
        
        public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "/certs/idp_public.pem")
        jwks_url = os.getenv("OIDC_JWKS_URL", "")

        self.static_public_key: Optional[str] = None
        self.jwks_client: Optional[PyJWKClient] = None

        if jwks_url:
            # Connected OIDC mode: fetches rotating public keys from IdP JWKS endpoint
            self.jwks_client = PyJWKClient(jwks_url, cache_keys=True)
        elif os.path.exists(public_key_path):
            # Air-gapped mode: loads pinned IdP public key from mounted volume
            with open(public_key_path, "r", encoding="utf-8") as f:
                self.static_public_key = f.read()
        else:
            raise RuntimeError(
                f"JWT verification misconfigured: neither OIDC_JWKS_URL nor {public_key_path} found."
            )

    def verify_token(self, token: str) -> User:
        try:
            if self.jwks_client:
                signing_key = self.jwks_client.get_signing_key_from_jwt(token).key
            else:
                signing_key = self.static_public_key

            # Cryptographically verify signature, expiration, issuer, and audience
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["exp", "iat", "sub", "iss", "aud", "clearance", "compartments"]
                },
            )

            return User(
                user_id=str(payload["sub"]),
                role=str(payload.get("role", "contractor")),
                clearance=int(payload["clearance"]),
                compartments=set(payload.get("compartments", [])),
            )

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired.",
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {e}",
            )

# Singleton dependency for FastAPI
authenticator = JWTAuthenticator()

def get_authenticated_user(authorization: str = Header(...)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must use Bearer scheme.",
        )
    token = authorization.removeprefix("Bearer ").strip()
    return authenticator.verify_token(token)
