"""
auth_admin.py — Admin authentication, JWT handling, and reset confirmation token management.
"""

import datetime
import logging
import os
import secrets
import time
from typing import Dict, Optional

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app import vault_client
from app.config import (
    ADMIN_JWT_VAULT_PATH,
    ADMIN_JWT_TTL_MINUTES,
    ADMIN_RESET_TOKEN_TTL_SECONDS,
)

logger = logging.getLogger("hpe.auth_admin")

_jwt_secret: str = ""
_jwt_algorithm: str = "HS256"

security = HTTPBearer(auto_error=False)

def load_jwt_secret() -> None:
    """Read signing key from Vault KV at secret/data/hpe/admin-jwt or env var."""
    global _jwt_secret, _jwt_algorithm
    
    # Check environment variable first (ensures stability across replicas)
    env_secret = os.getenv("ADMIN_JWT_SECRET")
    if env_secret:
        _jwt_secret = env_secret
        _jwt_algorithm = "HS256"
        logger.info("Loaded JWT signing secret from environment variable (ADMIN_JWT_SECRET).")
        return

    try:
        if vault_client._client and vault_client.is_connected():
            logger.info("Reading JWT secret from Vault KV...")
            response = vault_client._client.secrets.kv.v2.read_secret_version(
                path=ADMIN_JWT_VAULT_PATH,
                raise_on_deleted_version=False,
            )
            data = response.get("data", {}).get("data", {})
            signing_key = data.get("signing_key", "")
            algorithm = data.get("algorithm", "HS256")
            if signing_key:
                _jwt_secret = signing_key
                _jwt_algorithm = algorithm
                logger.info(f"Loaded JWT signing secret from Vault (path: {ADMIN_JWT_VAULT_PATH})")
                return
            else:
                logger.warning("Vault JWT secret exists but is empty. Generating fallback.")
        else:
            logger.warning("Vault client not connected. Generating fallback.")
    except Exception as e:
        logger.error(f"Failed to read JWT secret from Vault: {e}. Generating fallback.")

    # Fallback to local dev secret
    _jwt_secret = secrets.token_hex(32)
    _jwt_algorithm = "HS256"
    logger.info("Generated fallback JWT signing secret.")


def create_admin_token(username: str) -> str:
    """
    Create a signed JWT with claims:
      sub: username
      role: admin
      iat: issued-at timestamp
      exp: expiry (now + 30 min)
    Algorithm: HS256
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "role": "admin",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ADMIN_JWT_TTL_MINUTES)
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_jwt_algorithm)


def verify_token(token: str) -> dict:
    """Verify JWT and return decoded payload, or raise Exception."""
    return jwt.decode(token, _jwt_secret, algorithms=[_jwt_algorithm])


async def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """
    FastAPI Depends callable:
    1. Extract Bearer token from Authorization header
    2. Decode JWT with HS256 using Vault-stored secret
    3. Verify exp claim hasn't passed
    4. Return decoded claims
    5. Raise HTTPException(401) on any failure
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = verify_token(credentials.credentials)
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not authorized as admin")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Reset token management (for #7) ─────────────────────────────────────────

_pending_reset_tokens: Dict[str, float] = {}  # {token: expiry_timestamp}

def create_reset_token() -> str:
    """Generate a one-time token valid for 60 seconds."""
    token = secrets.token_urlsafe(32)
    _pending_reset_tokens[token] = time.time() + ADMIN_RESET_TOKEN_TTL_SECONDS
    return token


def validate_reset_token(token: str) -> bool:
    """Check token exists and hasn't expired. Consume it (one-time use)."""
    expiry = _pending_reset_tokens.pop(token, None)
    if expiry is None:
        return False
    return time.time() < expiry
