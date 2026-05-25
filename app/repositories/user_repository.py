"""User repository — async DB access for User model."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models.user import User
from app.domain.enums import UserRole
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    model = User

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    async def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_str(self, user_id_str: str) -> User | None:
        """Look up a user by string UUID — used after JWT decoding."""
        try:
            uid = uuid.UUID(user_id_str)
        except ValueError:
            return None
        return await self.get(uid)

    async def list_users(
        self,
        page: int = 1,
        page_size: int = 50,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[User], int]:
        stmt = select(User)
        count_stmt = select(User)

        if role is not None:
            stmt = stmt.where(User.role == role)
            count_stmt = count_stmt.where(User.role == role)
        if is_active is not None:
            stmt = stmt.where(User.is_active == is_active)
            count_stmt = count_stmt.where(User.is_active == is_active)

        total = await self.count(*(
            [User.role == role] if role else []
            + ([User.is_active == is_active] if is_active is not None else [])
        ))

        stmt = stmt.offset((page - 1) * page_size).limit(page_size).order_by(User.created_at.desc())
        result = await self._db.execute(stmt)
        return result.scalars().all(), total

    async def username_exists(self, username: str) -> bool:
        stmt = select(User.id).where(User.username == username).limit(1)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def email_exists(self, email: str) -> bool:
        stmt = select(User.id).where(User.email == email).limit(1)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none() is not None
