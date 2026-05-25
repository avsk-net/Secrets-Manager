"""
JWT token creation, validation, and revocation.

Token design:
  Access token:
    - Algorithm: HS256 (symmetric HMAC-SHA256)
    - Short TTL: 15 minutes by default
    - Carries: sub, username, role, scopes[], jti, iat, exp, iss, aud
    - NOT stored in DB (stateless) — revocation via jti blocklist in Redis
    - Why not RS256? RS256 (asymmetric) is better for multi-service setups
      where resource servers need to verify tokens without the signing key.
      For a single-service deployment, HS256 is simpler with equivalent security.
      Switch to RS256 when you add resource servers that need to verify JWTs.

  Refresh token:
    - Opaque: 32 bytes from secrets.token_urlsafe()
    - Stored as SHA-256 hash in the refresh_tokens table
    - Family-based rotation: reuse detection revokes the entire family
    - TTL: 7 days by default

JTI (JWT ID) revocation:
  We store revoked JTIs in Redis with TTL = token expiry time.
  This avoids DB lookups on every request while guaranteeing revoked
  tokens cannot be used (even if they haven't expired yet).
  Redis key: "revoked_jti:{jti}"

Token audience/issuer validation:
  Both `aud` and `iss` are validated on every token verification.
  Misconfigured tokens (e.g., from a different service) are rejected,
  preventing confusion attacks in multi-service environments.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as aioredis
from jose import JWTError, jwt

from app.config import get_settings
from app.domain.enums import ROLE_SCOPES, UserRole
from app.domain.schemas.auth import TokenPayload


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    user_id: uuid.UUID,
    username: str,
    role: UserRole,
    extra_scopes: list[str] | None = None,
) -> tuple[str, str]:
    """
    Create a signed JWT access token.

    Scopes are derived from the role (ROLE_SCOPES mapping) with optional
    extra_scopes for fine-grained per-user permissions.

    Returns:
        (access_token_str, jti)
        The jti is returned so the caller can store/track it if needed.
    """
    settings = get_settings()
    now = _now_utc()
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    jti = str(uuid.uuid4())

    # Build scope list from role definition
    role_scopes = [s.value for s in ROLE_SCOPES.get(role, frozenset())]
    all_scopes = list(set(role_scopes + (extra_scopes or [])))

    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role.value,
        "scopes": all_scopes,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def create_refresh_token() -> tuple[str, str]:
    """
    Create an opaque refresh token.

    Returns:
        (raw_token, token_hash)
        - raw_token: sent to the client (never stored)
        - token_hash: SHA-256 hex digest stored in DB

    Using secrets.token_urlsafe(32) gives 256 bits of entropy —
    resistant to brute-force even without rate limiting.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Compute the SHA-256 hash of a refresh token for DB lookup."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def verify_access_token(token: str) -> TokenPayload:
    """
    Verify and decode a JWT access token.

    Validation steps (all enforced by python-jose):
    1. Signature verification (HS256 with secret key)
    2. Expiry check (exp claim)
    3. Not-before check (nbf, if present)
    4. Audience check (aud == jwt_audience setting)
    5. Issuer check (iss == jwt_issuer setting)

    Returns:
        TokenPayload with all claims.

    Raises:
        jose.JWTError: on any validation failure (expired, invalid sig, wrong aud/iss)
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except JWTError as exc:
        raise JWTError(f"Token validation failed: {exc}") from exc

    return TokenPayload(**payload)


async def revoke_access_token(jti: str, redis_client: aioredis.Redis, ttl_seconds: int) -> None:
    """
    Add a JTI to the revocation blocklist in Redis.

    The key expires after the token's natural TTL — no need for cleanup.
    Pattern: "revoked_jti:<jti>" → "1"
    """
    key = f"revoked_jti:{jti}"
    await redis_client.setex(key, ttl_seconds, "1")


async def is_token_revoked(jti: str, redis_client: aioredis.Redis) -> bool:
    """Check if a JTI is in the Redis revocation blocklist."""
    key = f"revoked_jti:{jti}"
    return bool(await redis_client.exists(key))


def get_token_remaining_ttl(exp: int) -> int:
    """
    Compute seconds until token expiry.

    Used to set the correct TTL when adding a JTI to the revocation list —
    we don't want to keep revoked JTIs in Redis longer than necessary.
    """
    now = int(_now_utc().timestamp())
    remaining = exp - now
    return max(remaining, 0)
