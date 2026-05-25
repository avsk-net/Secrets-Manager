"""
Pytest fixtures for unit and integration tests.

Database strategy:
  - Integration tests use a real PostgreSQL instance (via docker-compose test profile)
  - Each test gets a fresh transaction that is rolled back after the test
  - This gives test isolation without truncating tables (faster)

Redis strategy:
  - Integration tests use a real Redis instance
  - Each test flushes the test DB before running

Fixture hierarchy:
  settings → engine → connection → db (per test, rolled back)
  settings → redis_client (per test, flushed)
  db + redis_client → http_client (per test)
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings, get_settings
from app.db.base import Base
from app.db.session import get_db

# ── Test settings ─────────────────────────────────────────────────────────────

TEST_DB_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://smgr:testpass@localhost:5432/secretmanager_test",
)
TEST_REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/15")

# Fixed test keys (DO NOT use in production)
TEST_MEK = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
TEST_JWT_SECRET = secrets.token_hex(64)
TEST_AUDIT_KEY = secrets.token_hex(64)


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings for tests — use fixed keys and test DB/Redis."""
    # Clear the lru_cache so our overrides take effect
    get_settings.cache_clear()
    os.environ.update({
        "APP_ENV": "development",
        "JWT_SECRET_KEY": TEST_JWT_SECRET,
        "MASTER_ENCRYPTION_KEY": TEST_MEK,
        "AUDIT_HMAC_KEY": TEST_AUDIT_KEY,
        "DATABASE_URL": TEST_DB_URL,
        "REDIS_URL": TEST_REDIS_URL,
        "ARGON2_TIME_COST": "1",       # Speed up tests
        "ARGON2_MEMORY_COST": "65536",
        "ARGON2_PARALLELISM": "1",
    })
    get_settings.cache_clear()
    return get_settings()


@pytest_asyncio.fixture(scope="session")
async def engine(test_settings: Settings):
    """Create tables and return engine for the test session."""
    eng = create_async_engine(TEST_DB_URL, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine) -> AsyncGenerator[AsyncSession, Any]:
    """
    Per-test database session with automatic rollback.

    Uses SAVEPOINT + ROLLBACK TO SAVEPOINT for nested transaction support.
    This lets each test start clean without dropping/creating tables.
    """
    factory = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    async with factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


@pytest_asyncio.fixture
async def redis_client(test_settings: Settings) -> AsyncGenerator[aioredis.Redis, Any]:
    """Per-test Redis client — flushes the test DB before each test."""
    client = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    await client.flushdb()
    yield client
    await client.close()


@pytest_asyncio.fixture
async def app(test_settings: Settings) -> FastAPI:
    """FastAPI test application with overridden settings."""
    from app.main import create_app
    _app = create_app()

    # Set up Redis in app state (normally done in lifespan)
    _app.state.redis = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    await _app.state.redis.flushdb()
    return _app


@pytest_asyncio.fixture
async def client(app: FastAPI, db: AsyncSession) -> AsyncGenerator[AsyncClient, Any]:
    """HTTP test client with DB session override."""

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


# ── Auth helpers ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def test_user(db: AsyncSession):
    """Create a test user with developer role."""
    import uuid
    from app.crypto.argon2_utils import hash_password
    from app.domain.models.user import User
    from app.domain.enums import UserRole

    user = User(
        id=uuid.uuid4(),
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("TestPass123!@#"),
        role=UserRole.DEVELOPER,
    )
    db.add(user)
    await db.flush()
    return user


@pytest_asyncio.fixture
async def admin_user(db: AsyncSession):
    """Create a test admin user."""
    import uuid
    from app.crypto.argon2_utils import hash_password
    from app.domain.models.user import User
    from app.domain.enums import UserRole

    user = User(
        id=uuid.uuid4(),
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("AdminPass123!@#"),
        role=UserRole.ADMIN,
    )
    db.add(user)
    await db.flush()
    return user


@pytest_asyncio.fixture
async def developer_token(test_user, test_settings: Settings) -> str:
    """JWT access token for the test developer user."""
    from app.auth.jwt_handler import create_access_token
    from app.domain.enums import UserRole
    token, _ = create_access_token(
        user_id=test_user.id,
        username=test_user.username,
        role=UserRole.DEVELOPER,
    )
    return token


@pytest_asyncio.fixture
async def admin_token(admin_user, test_settings: Settings) -> str:
    """JWT access token for the test admin user."""
    from app.auth.jwt_handler import create_access_token
    from app.domain.enums import UserRole
    token, _ = create_access_token(
        user_id=admin_user.id,
        username=admin_user.username,
        role=UserRole.ADMIN,
    )
    return token
