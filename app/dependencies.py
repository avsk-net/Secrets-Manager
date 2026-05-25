"""
Shared FastAPI application-level dependencies.

These are distinct from auth dependencies (app/auth/dependencies.py).
They provide infrastructure-level objects: DB sessions, Redis clients, etc.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as aioredis
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db as _get_db


async def get_db() -> AsyncGenerator[AsyncSession, Any]:
    """Re-export the DB session dependency for easier imports."""
    async for session in _get_db():
        yield session


async def get_redis_from_state(request: Request) -> aioredis.Redis:
    """Get the Redis client from app state (initialized in lifespan)."""
    return request.app.state.redis
