"""
RefreshToken model — stored representation of issued refresh tokens.

Security design:
- The actual token value is NEVER stored. Only the SHA-256 hash is persisted.
  If the DB is compromised, raw tokens cannot be extracted.
- token_family groups tokens issued via refresh-rotation:
  if an old (revoked) token in a family is presented, the ENTIRE family
  is immediately revoked — this detects refresh token theft.
- is_revoked flag: set when the token is used (rotation) or explicitly revoked.
- Expired tokens are cleaned up by a Celery background task.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin


class RefreshToken(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SHA-256 hex digest of the raw token — never the raw token itself
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # All tokens in a family share this UUID; reuse-attack detection revokes all
    family: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Request metadata for forensics — IP stored as INET for subnet queries
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship back to User
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        back_populates="refresh_tokens",
        lazy="noload",
    )

    __table_args__ = (
        Index("ix_refresh_tokens_user_family", "user_id", "family"),
        Index("ix_refresh_tokens_expires", "expires_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"revoked={self.is_revoked}>"
        )
