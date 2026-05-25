"""
Async SQLAlchemy session management.

Key design decisions:
- Using AsyncEngine + AsyncSession for non-blocking I/O in FastAPI
- NullPool for async engines — each connection is per-request, avoids
  the "connection is checked out in multiple green-threads" bug
- Connection pool parameters tuned for production: pool_size + max_overflow
  should match Postgres max_connections / num_api_workers
- Session factory is module-level; do NOT create engine per request
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
        echo=settings.database_echo,
        # pool_pre_ping ensures stale connections are detected and recycled
        # before being handed to a request handler — avoids cryptic DB errors
        pool_pre_ping=True,
        # json_serializer/deserializer can be customised here for custom types
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,  # Avoid lazy-load errors after commit in async context
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, Any]:
    """
    FastAPI dependency that yields an async DB session per request.

    The session is automatically closed (and rolled back on exception)
    when the request context exits.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_engine() -> None:
    """Gracefully dispose the connection pool — called on app shutdown."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
