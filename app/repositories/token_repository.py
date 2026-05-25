"""Refresh token repository — async DB access for RefreshToken model."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models.token import RefreshToken
from app.repositories.base import BaseRepository


class TokenRepository(BaseRepository[RefreshToken]):
    model = RefreshToken

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Find an active, non-expired refresh token by its hash."""
        now = datetime.now(timezone.utc)
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,  # noqa: E712
            RefreshToken.expires_at > now,
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_hash_any_status(self, token_hash: str) -> RefreshToken | None:
        """Find ANY refresh token by hash (including revoked) — for reuse detection."""
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def revoke_token(self, token_id: uuid.UUID) -> None:
        await self._db.execute(
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(is_revoked=True)
        )

    async def revoke_family(self, family: uuid.UUID) -> int:
        """
        Revoke ALL tokens in a refresh token family.

        Called when a reuse attack is detected (old revoked token presented).
        This invalidates all currently-valid tokens in the rotation chain,
        forcing the user to re-authenticate.

        Returns the number of tokens revoked.
        """
        result = await self._db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family == family,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
            .values(is_revoked=True)
        )
        return result.rowcount

    async def revoke_all_for_user(self, user_id: uuid.UUID) -> int:
        """Revoke all refresh tokens for a user — used on logout, account lock."""
        result = await self._db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
            .values(is_revoked=True)
        )
        return result.rowcount

    async def delete_expired(self) -> int:
        """Purge expired tokens — called by Celery cleanup task."""
        now = datetime.now(timezone.utc)
        result = await self._db.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < now)
        )
        return result.rowcount
