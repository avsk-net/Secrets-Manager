"""
Authentication endpoints — login, refresh, logout, change password.

Endpoint design:
  POST /auth/login     — Returns access + refresh tokens
  POST /auth/refresh   — Exchange refresh token for new pair
  POST /auth/logout    — Revoke tokens
  POST /auth/change-password — Change own password

Security notes:
  - Login uses OAuth2 password flow for Swagger compatibility
  - All errors return the same 401 message (no username enumeration)
  - Tokens are returned in the response body (not cookies) so this
    API is stateless and CSRF-free by design. If you add cookie transport,
    implement CSRF tokens (SameSite=Strict is not sufficient for all browsers).
  - The refresh endpoint is the ONLY place that accepts a refresh token
    in the request body — never in the URL or query params.
"""

from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, get_redis
from app.db.session import get_db
from app.domain.schemas.auth import (
    ChangePasswordRequest,
    LogoutRequest,
    LoginRequest,
    RefreshRequest,
    TokenPayload,
    TokenResponse,
)
from app.services.auth_service import AccountLockedError, AuthenticationError, AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_request_meta(request: Request) -> dict:
    """Extract request metadata for audit logging."""
    return {
        "ip_address": request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                      or (request.client.host if request.client else None),
        "user_agent": request.headers.get("User-Agent"),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive tokens",
    responses={
        401: {"description": "Invalid credentials"},
        423: {"description": "Account locked"},
        429: {"description": "Rate limit exceeded"},
    },
)
async def login(
    credentials: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> TokenResponse:
    """
    Authenticate with username + password, receive JWT access token and refresh token.

    The access token expires in 15 minutes; use /auth/refresh to get a new one.
    The refresh token expires in 7 days and is rotated on each use.
    """
    meta = _get_request_meta(request)
    auth_svc = AuthService(db, redis_client)

    try:
        return await auth_svc.login(
            username=credentials.username,
            password=credentials.password,
            ip_address=meta["ip_address"],
            user_agent=meta["user_agent"],
            request_id=meta["request_id"],
        )
    except AccountLockedError as e:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(e),
        )
    except AuthenticationError:
        # NEVER leak which part of the credentials was wrong
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using refresh token",
    responses={
        401: {"description": "Invalid or expired refresh token"},
    },
)
async def refresh_tokens(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> TokenResponse:
    """
    Exchange a refresh token for a new access + refresh token pair.

    The old refresh token is immediately invalidated.
    Presenting a previously-used refresh token revokes the entire token family
    (indicates potential token theft).
    """
    meta = _get_request_meta(request)
    auth_svc = AuthService(db, redis_client)

    try:
        return await auth_svc.refresh_tokens(
            raw_refresh_token=body.refresh_token,
            ip_address=meta["ip_address"],
            user_agent=meta["user_agent"],
            request_id=meta["request_id"],
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke tokens and end session",
)
async def logout(
    body: LogoutRequest,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> None:
    """
    Revoke the refresh token and blacklist the current access token JTI.

    After logout, the access token cannot be used even within its remaining TTL.
    """
    meta = _get_request_meta(request)
    auth_svc = AuthService(db, redis_client)
    await auth_svc.logout(
        raw_refresh_token=body.refresh_token,
        access_jti=token.jti,
        access_exp=token.exp,
        actor_id=token.sub,
        actor_username=token.username,
        ip_address=meta["ip_address"],
        user_agent=meta["user_agent"],
        request_id=meta["request_id"],
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change current user's password",
)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> None:
    """
    Change the authenticated user's password.

    Requires current password for verification (prevents session hijack misuse).
    After password change, all existing refresh tokens are revoked.
    """
    from app.crypto.argon2_utils import hash_password, verify_password
    from app.repositories.user_repository import UserRepository
    from app.repositories.token_repository import TokenRepository
    import uuid

    meta = _get_request_meta(request)
    user_repo = UserRepository(db)
    token_repo = TokenRepository(db)

    user = await user_repo.get(uuid.UUID(token.sub))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    user.password_hash = hash_password(body.new_password)

    # Revoke all refresh tokens — new password = new session required
    await token_repo.revoke_all_for_user(user.id)

    # Blacklist the current access token JTI too
    from app.auth.jwt_handler import get_token_remaining_ttl, revoke_access_token
    remaining = get_token_remaining_ttl(token.exp)
    if remaining > 0:
        await revoke_access_token(token.jti, redis_client, remaining)
