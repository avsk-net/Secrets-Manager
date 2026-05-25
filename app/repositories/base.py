"""Generic async repository base class."""

from __future__ import annotations

import uuid
from typing import Any, Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base

ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """
    Thin async repository providing standard CRUD operations.

    Repositories are the ONLY layer that talks to SQLAlchemy.
    Services receive domain objects, not query results.
    This separation makes the data layer swappable and testable.
    """

    model: type[ModelT]

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get(self, id: uuid.UUID) -> ModelT | None:
        return await self._db.get(self.model, id)

    async def create(self, obj: ModelT) -> ModelT:
        self._db.add(obj)
        await self._db.flush()
        return obj

    async def delete(self, obj: ModelT) -> None:
        await self._db.delete(obj)
        await self._db.flush()

    async def count(self, *where: Any) -> int:
        stmt = select(func.count()).select_from(self.model)
        if where:
            stmt = stmt.where(*where)
        result = await self._db.execute(stmt)
        return result.scalar_one()
