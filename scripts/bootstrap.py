"""
Bootstrap script — creates the first super_admin account.

Run ONCE after initial deployment:
  python scripts/bootstrap.py

Security notes:
  - Credentials are read from environment variables
  - Script is idempotent: does nothing if super_admin already exists
  - Clear BOOTSTRAP_ADMIN_PASSWORD from the environment after running
  - Log shows username/email but NEVER the password
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


async def bootstrap() -> None:
    from app.config import get_settings
    from app.crypto.argon2_utils import hash_password
    from app.db.session import close_engine, get_session_factory
    from app.domain.enums import UserRole
    from app.domain.models.user import User
    from app.repositories.user_repository import UserRepository

    settings = get_settings()
    username = settings.bootstrap_admin_username
    email = settings.bootstrap_admin_email
    password = settings.bootstrap_admin_password

    if not password or len(password) < 16:
        print("ERROR: BOOTSTRAP_ADMIN_PASSWORD must be at least 16 characters", file=sys.stderr)
        sys.exit(1)

    factory = get_session_factory()
    async with factory() as session:
        repo = UserRepository(session)

        # Idempotent: skip if super_admin exists
        if await repo.username_exists(username):
            print(f"Bootstrap skipped: user '{username}' already exists")
            return

        user = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=UserRole.SUPER_ADMIN,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    print(f"Bootstrap complete: super_admin '{username}' ({email}) created")
    print("ACTION REQUIRED: Remove BOOTSTRAP_ADMIN_PASSWORD from your environment")

    await close_engine()


if __name__ == "__main__":
    asyncio.run(bootstrap())
