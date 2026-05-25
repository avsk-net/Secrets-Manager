"""
Authentication service — login, logout, token refresh, account management.

Security design:
  Brute-force protection:
    - Failed login increments failed_login_attempts on the user record
    - After MAX_FAILED_ATTEMPTS, account is soft-locked for LOCKOUT_MINUTES
    - Lockout is time-based (auto-unlocks) not permanent (admin can also unlock)
    - Rate limiting (in middleware) provides the first line of defense

  Timing attack prevention:
    - Always call Argon2 verify even if the user doesn't exist (dummy hash)
    - This ensures the login response time is the same for valid/invalid usernames
    - Without this: timing difference reveals whether a username exists

  Refresh token security:
    - Tokens are stored as SHA-256 hashes (raw token sent to client only)
    - Refresh token rotation: every use generates a new pair
    - Reuse detection: if a revoked token is presented, revoke the entire family
      (indicates token theft — the victim and attacker can't both have the token)

  Session termination:
    - Logout revokes the refresh token and blacklists the access JTI
    - This ensures the access token cannot be used for its remaining TTL
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    get_token_remaining_ttl,
    hash_refresh_token,
    revoke_access_token,
)
from app.config import get_settings
from app.crypto.argon2_utils import hash_password, needs_rehash, verify_password
from app.domain.enums import AuditEventType, AuditResult, ResourceType, UserRole
from app.domain.models.token import RefreshToken
from app.domain.models.user import User
from app.domain.schemas.auth import TokenResponse
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 30

# Dummy hash for constant-time comparison when username doesn't exist
# Pre-computed Argon2id hash of "dummy_password_NEVER_USED" — just to consume time
_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHR0ZXN0c2FsdA$notarealhashjustfordummyverification"


class AuthenticationError(Exception):
    """Raised when authentication fails — message is user-facing safe."""

    def __init__(self, message: str = "Invalid credentials") -> None:
        super().__init__(message)


class AccountLockedError(Exception):
    """Raised when the account is locked."""

    def __init__(self, until: datetime | None = None) -> None:
        self.until = until
        msg = "Account is locked"
        if until:
            msg += f" until {until.isoformat()}"
        super().__init__(msg)


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        redis_client: aioredis.Redis,
    ) -> None:
        self._db = db
        self._redis = redis_client
        self._settings = get_settings()
        self._user_repo = UserRepository(db)
        self._token_repo = TokenRepository(db)
        self._audit = AuditLogger(db)

    async def login(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> TokenResponse:
        """
        Authenticate a user and issue access + refresh tokens.

        Always takes approximately the same time regardless of whether the
        username exists — prevents username enumeration via timing.
        """
        user = await self._user_repo.get_by_username(username)

        # Always run Argon2 (timing attack prevention)
        # Even for non-existent users, we verify against a dummy hash
        hash_to_check = user.password_hash if user else _DUMMY_HASH
        password_valid = verify_password(hash_to_check, password)

        if user is None or not password_valid:
            # Record failed attempt only for real users (don't reveal existence)
            if user is not None:
                await self._record_failed_login(user)
            await self._audit.emit(
                event_type=AuditEventType.AUTH_LOGIN_FAILURE,
                action="login",
                result=AuditResult.FAILURE,
                resource_type=ResourceType.USER,
                actor_id=str(user.id) if user else None,
                actor_username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                details={"username": username},
                error_message="Invalid credentials",
            )
            raise AuthenticationError()

        # Check account status
        if not user.is_active:
            raise AuthenticationError("Account is inactive")

        if user.is_locked:
            raise AccountLockedError()

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise AccountLockedError(until=user.locked_until)

        # Successful auth — reset failure counter and update last login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)

        # Transparent Argon2 parameter upgrade on successful login
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        # Issue tokens
        access_token, jti = create_access_token(
            user_id=user.id,
            username=user.username,
            role=UserRole(user.role),
        )
        raw_refresh, refresh_hash = create_refresh_token()

        # Create a new token family for this session
        family = uuid.uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self._settings.jwt_refresh_token_expire_days
        )

        token_record = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=refresh_hash,
            family=family,
            is_revoked=False,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self._token_repo.create(token_record)

        await self._audit.emit(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            action="login",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.USER,
            actor_id=str(user.id),
            actor_username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            token_type="bearer",
            expires_in=self._settings.jwt_access_token_expire_minutes * 60,
            scope=[s for s in ROLE_SCOPES_STR(UserRole(user.role))],
        )

    async def refresh_tokens(
        self,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> TokenResponse:
        """
        Exchange a valid refresh token for a new access + refresh token pair.

        Implements refresh token rotation with reuse detection:
        1. If token is valid → issue new pair, revoke old token
        2. If token is already revoked → revoke entire family (theft detected)
        3. If token doesn't exist or expired → reject
        """
        token_hash = hash_refresh_token(raw_refresh_token)

        # Check for revoked token (reuse attack detection)
        any_token = await self._token_repo.get_by_hash_any_status(token_hash)
        if any_token and any_token.is_revoked:
            # SECURITY: Revoked token reuse → revoke entire family
            revoked_count = await self._token_repo.revoke_family(any_token.family)
            await self._audit.emit(
                event_type=AuditEventType.AUTH_TOKEN_FAMILY_REVOKED,
                action="token_family_revoke",
                result=AuditResult.DENIED,
                resource_type=ResourceType.TOKEN,
                actor_id=str(any_token.user_id),
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                details={"revoked_count": revoked_count},
                error_message="Refresh token reuse detected",
            )
            raise AuthenticationError("Token reuse detected")

        # Get the active token
        token_record = await self._token_repo.get_by_hash(token_hash)
        if not token_record:
            raise AuthenticationError("Invalid or expired refresh token")

        user = await self._user_repo.get(token_record.user_id)
        if not user or not user.is_active or user.is_locked:
            raise AuthenticationError("Account is inactive or locked")

        # Revoke the used token
        await self._token_repo.revoke_token(token_record.id)

        # Issue new pair (same family — rotation chain)
        access_token, _ = create_access_token(
            user_id=user.id,
            username=user.username,
            role=UserRole(user.role),
        )
        raw_refresh, refresh_hash = create_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self._settings.jwt_refresh_token_expire_days
        )

        new_token = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=refresh_hash,
            family=token_record.family,  # Same family — maintains rotation chain
            is_revoked=False,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self._token_repo.create(new_token)

        await self._audit.emit(
            event_type=AuditEventType.AUTH_TOKEN_REFRESH,
            action="token_refresh",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.TOKEN,
            actor_id=str(user.id),
            actor_username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            token_type="bearer",
            expires_in=self._settings.jwt_access_token_expire_minutes * 60,
            scope=ROLE_SCOPES_STR(UserRole(user.role)),
        )

    async def logout(
        self,
        raw_refresh_token: str,
        access_jti: str,
        access_exp: int,
        actor_id: str,
        actor_username: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Revoke refresh token and blacklist the access JTI in Redis."""
        token_hash = hash_refresh_token(raw_refresh_token)
        token_record = await self._token_repo.get_by_hash(token_hash)
        if token_record:
            await self._token_repo.revoke_token(token_record.id)

        # Blacklist the access token JTI until it naturally expires
        remaining_ttl = get_token_remaining_ttl(access_exp)
        if remaining_ttl > 0:
            await revoke_access_token(access_jti, self._redis, remaining_ttl)

        await self._audit.emit(
            event_type=AuditEventType.AUTH_LOGOUT,
            action="logout",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.USER,
            actor_id=actor_id,
            actor_username=actor_username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )

    async def _record_failed_login(self, user: User) -> None:
        """Increment failed attempts and lock account if threshold exceeded."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            await self._audit.emit(
                event_type=AuditEventType.AUTH_ACCOUNT_LOCKED,
                action="account_lock",
                result=AuditResult.FAILURE,
                resource_type=ResourceType.USER,
                actor_id=str(user.id),
                actor_username=user.username,
                details={"failed_attempts": user.failed_login_attempts},
            )


def ROLE_SCOPES_STR(role: UserRole) -> list[str]:
    from app.domain.enums import ROLE_SCOPES
    return [s.value for s in ROLE_SCOPES.get(role, frozenset())]
