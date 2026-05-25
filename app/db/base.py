"""
SQLAlchemy declarative base and shared mixins.

Using SQLAlchemy 2.0's new DeclarativeBase class (replaces declarative_base()).
All models import from here to ensure they share the same metadata instance,
which Alembic needs for autogenerate to work correctly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Project-wide declarative base.

    All SQLAlchemy models must inherit from this class.
    Do not create additional bases — Alembic's autogenerate
    only tracks models registered with a single metadata.
    """

    pass


class TimestampMixin:
    """
    Adds `created_at` / `updated_at` columns managed by Python-side defaults.

    Python lambdas (not server-side SQL functions) are used for default/onupdate
    so SQLAlchemy always knows the value before INSERT/UPDATE.  Server-side
    server_default is kept only as a fallback for raw-SQL inserts that bypass
    SQLAlchemy (e.g. migrations, seed scripts).

    Using server-side onupdate=func.now() causes SQLAlchemy to expire the column
    after every UPDATE (because the DB-generated value is unknown in Python), which
    in an async context triggers a MissingGreenlet error when the attribute is
    accessed later.  Python-side onupdate avoids that entirely.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UUIDPrimaryKeyMixin:
    """
    Adds a `id` UUID primary key with a server-side default.

    UUIDs prevent sequential ID enumeration attacks — an attacker cannot
    guess `id=2` after seeing `id=1`.  gen_random_uuid() uses the PG PRNG,
    which is cryptographically secure.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        nullable=False,
    )
