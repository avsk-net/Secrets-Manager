"""
FastAPI authentication and authorization dependencies.

Usage in endpoints:
    @router.get("/secrets")
    async def list_secrets(
        token: TokenPayload = Depends(get_current_user),
        _: None = Depends(require_scope(Scope.SECRETS_LIST)),
    ):
        ...

Or combined:
    @router.delete("/secrets/{id}")
    async def delete_secret(
        token: TokenPayload = Depends(require_scope_dep(Scope.SECRETS_DELETE)),
    ):
        ...

Design:
- All auth failures return 401 (Unauthorized) — not 403
- Permission failures return 403 (Forbidden)
- The distinction matters for clients: 401 = retry with new token, 403 = give up
- WWW-Authenticate header included on 401 per RFC 7235
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_handler import is_token_revoked, verify_access_token
from app.auth.rbac import PermissionDenied, has_scope
from app.config import get_settings
from app.db.session import get_db
from app.domain.enums import Scope, UserRole
from app.domain.schemas.auth import TokenPayload

# OAuth2 scheme — tells OpenAPI/Swagger the token endpoint location
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    scopes={s.value: s.value for s in Scope},
)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

_ACCOUNT_INACTIVE = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Account is inactive or locked",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_redis(request: Request) -> aioredis.Redis:
    """Get the Redis client from app state (set in main.py lifespan)."""
    return request.app.state.redis


async def get_current_token(
    token: str = Depends(oauth2_scheme),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> TokenPayload:
    """
    Validate the Bearer token and return its decoded payload.

    Steps:
    1. Decode and verify JWT signature, expiry, aud, iss
    2. Check JTI against Redis revocation blocklist
    """
    try:
        payload = verify_access_token(token)
    except JWTError:
        raise _UNAUTHORIZED

    # Check revocation blocklist — fast O(1) Redis lookup
    if await is_token_revoked(payload.jti, redis_client):
        raise _UNAUTHORIZED

    return payload


async def get_current_user(
    token: TokenPayload = Depends(get_current_token),
    db: AsyncSession = Depends(get_db),
) -> TokenPayload:
    """
    Validate token and verify the associated user is still active.

    This extra DB check prevents revoked-user tokens from working
    during the access token TTL window.
    For high-traffic deployments, cache the user active status in Redis
    to avoid a DB hit on every request.
    """
    from app.repositories.user_repository import UserRepository

    repo = UserRepository(db)
    user = await repo.get_by_id_str(token.sub)

    if user is None or not user.is_active or user.is_locked:
        raise _ACCOUNT_INACTIVE

    return token


def require_scope(scope: Scope) -> Callable:
    """
    Dependency factory: raises 403 if the token lacks the required scope.

    Usage:
        @router.get("/secrets", dependencies=[Depends(require_scope(Scope.SECRETS_LIST))])
    """

    async def _check(token: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if not has_scope(token, scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required scope: {scope.value}",
            )
        return token

    return _check


def require_role(minimum_role: UserRole) -> Callable:
    """
    Dependency factory: raises 403 if the token's role is below minimum.

    Uses the ordering defined in UserRole.__ge__ (READONLY < DEVELOPER < ADMIN < SUPER_ADMIN).
    """

    async def _check(token: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        try:
            token_role = UserRole(token.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role in token",
            )
        if not (token_role >= minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {minimum_role.value} or higher required",
            )
        return token

    return _check


# Pre-built convenience dependencies for common role requirements
require_admin = require_role(UserRole.ADMIN)
require_super_admin = require_role(UserRole.SUPER_ADMIN)
