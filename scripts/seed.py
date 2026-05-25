"""
Development seed script — populates the database with sample data.

DO NOT run in production. Creates:
  - Users of each role
  - Sample secrets of each type
  - Simulates version history

Passwords are printed to stdout (development only).
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


SEED_USERS = [
    {"username": "dev1", "email": "dev1@example.com", "password": "DevPass123!@#", "role": "developer"},
    {"username": "dev2", "email": "dev2@example.com", "password": "DevPass456!@#", "role": "developer"},
    {"username": "viewer", "email": "viewer@example.com", "password": "ViewPass123!@#", "role": "readonly"},
    {"username": "sysadmin", "email": "sysadmin@example.com", "password": "AdminPass123!@#", "role": "admin"},
]

SEED_SECRETS = [
    {"name": "prod/db/password", "namespace": "production", "type": "kv", "value": "prod_db_s3cr3t"},
    {"name": "staging/db/password", "namespace": "staging", "type": "kv", "value": "staging_pass"},
    {"name": "prod/api/config", "namespace": "production", "type": "json",
     "value": {"host": "api.internal", "port": 443, "timeout": 30}},
    {"name": "prod/tls/cert", "namespace": "production", "type": "kv",
     "value": "-----BEGIN CERTIFICATE-----\nMIIFakeCert\n-----END CERTIFICATE-----"},
]


async def seed() -> None:
    from app.config import get_settings
    from app.crypto.argon2_utils import hash_password
    from app.db.session import close_engine, get_session_factory
    from app.domain.enums import UserRole, SecretType
    from app.domain.models.user import User
    from app.repositories.user_repository import UserRepository

    settings = get_settings()
    if settings.app_env == "production":
        print("ERROR: Cannot seed production database", file=sys.stderr)
        sys.exit(1)

    factory = get_session_factory()

    async with factory() as session:
        user_repo = UserRepository(session)

        created_users = []
        for u in SEED_USERS:
            if not await user_repo.username_exists(u["username"]):
                user = User(
                    id=uuid.uuid4(),
                    username=u["username"],
                    email=u["email"],
                    password_hash=hash_password(u["password"]),
                    role=UserRole(u["role"]),
                )
                session.add(user)
                created_users.append(u)
                print(f"  Created user: {u['username']} / {u['password']}")

        await session.flush()

        # Get first developer to own secrets
        developer = await user_repo.get_by_username("dev1")
        if developer is None:
            developer = await user_repo.get_by_username(SEED_USERS[0]["username"])

        await session.commit()

    print(f"\nSeed complete: {len(created_users)} users created")
    print("Sample credentials (development only):")
    for u in SEED_USERS:
        print(f"  {u['username']}: {u['password']}")

    await close_engine()


if __name__ == "__main__":
    asyncio.run(seed())
