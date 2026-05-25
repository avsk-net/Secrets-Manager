"""
User model — stores identity, credentials, and role assignment.

Password is stored as an Argon2id hash (see app/crypto/argon2_utils.py).
The plaintext password NEVER appears in this model, logs, or anywhere
outside the authentication layer.

Brute-force protection:
- failed_login_attempts incremented on each bad password
- locked_until set when threshold exceeded (see auth_service.py)
- is_locked flag for permanent admin-triggered lockout
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.domain.enums import UserRole


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # Argon2id hash — never store plaintext or any reversible encoding
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)

    role: Mapped[UserRole] = mapped_column(
        String(50),
        nullable=False,
        default=UserRole.READONLY,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Admin-controlled hard lock (e.g., account compromise suspected)
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Automatic brute-force lockout
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships (lazy="noload" avoids N+1 in async context by default)
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(  # noqa: F821
        "RefreshToken",
        back_populates="user",
        lazy="noload",
        cascade="all, delete-orphan",
    )
    created_secrets: Mapped[list["Secret"]] = relationship(  # noqa: F821
        "Secret",
        foreign_keys="[Secret.created_by_id]",
        back_populates="created_by",
        lazy="noload",
    )

    __table_args__ = (
        Index("ix_users_role", "role"),
        Index("ix_users_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role}>"
