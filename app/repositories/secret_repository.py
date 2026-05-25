"""Secret and SecretVersion repository."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domain.models.secret import KeyMetadata, Secret, SecretVersion
from app.repositories.base import BaseRepository


class SecretRepository(BaseRepository[Secret]):
    model = Secret

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    async def get_by_name_namespace(
        self,
        name: str,
        namespace: str,
        include_deleted: bool = False,
    ) -> Secret | None:
        stmt = select(Secret).where(
            Secret.name == name,
            Secret.namespace == namespace,
        )
        if not include_deleted:
            stmt = stmt.where(Secret.is_deleted == False)  # noqa: E712
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_current_version(self, secret_id: uuid.UUID) -> Secret | None:
        """Load a secret and eagerly fetch its current version."""
        stmt = (
            select(Secret)
            .options(selectinload(Secret.versions))
            .where(Secret.id == secret_id, Secret.is_deleted == False)  # noqa: E712
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_secrets(
        self,
        namespace: str | None = None,
        page: int = 1,
        page_size: int = 50,
        include_deleted: bool = False,
    ) -> tuple[list[Secret], int]:
        conditions = []
        if namespace:
            conditions.append(Secret.namespace == namespace)
        if not include_deleted:
            conditions.append(Secret.is_deleted == False)  # noqa: E712

        count = await self.count(*conditions)

        stmt = select(Secret)
        if conditions:
            stmt = stmt.where(*conditions)
        stmt = stmt.offset((page - 1) * page_size).limit(page_size).order_by(
            Secret.updated_at.desc()
        )
        result = await self._db.execute(stmt)
        return result.scalars().all(), count

    async def soft_delete(
        self,
        secret_id: uuid.UUID,
        deleted_by_id: uuid.UUID,
    ) -> bool:
        result = await self._db.execute(
            update(Secret)
            .where(Secret.id == secret_id, Secret.is_deleted == False)  # noqa: E712
            .values(
                is_deleted=True,
                deleted_at=datetime.now(timezone.utc),
                deleted_by_id=deleted_by_id,
            )
        )
        return result.rowcount > 0

    async def restore(self, secret_id: uuid.UUID) -> bool:
        result = await self._db.execute(
            update(Secret)
            .where(Secret.id == secret_id, Secret.is_deleted == True)  # noqa: E712
            .values(is_deleted=False, deleted_at=None, deleted_by_id=None)
        )
        return result.rowcount > 0

    async def name_exists(self, name: str, namespace: str) -> bool:
        stmt = (
            select(Secret.id)
            .where(Secret.name == name, Secret.namespace == namespace, Secret.is_deleted == False)  # noqa: E712
            .limit(1)
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none() is not None


class SecretVersionRepository(BaseRepository[SecretVersion]):
    model = SecretVersion

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    async def get_current_version(self, secret_id: uuid.UUID) -> SecretVersion | None:
        """Get the current (latest active) version of a secret."""
        stmt = (
            select(SecretVersion)
            .options(selectinload(SecretVersion.key))
            .where(
                SecretVersion.secret_id == secret_id,
                SecretVersion.is_current == True,  # noqa: E712
            )
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_version(self, secret_id: uuid.UUID, version: int) -> SecretVersion | None:
        """Get a specific version number of a secret."""
        stmt = (
            select(SecretVersion)
            .options(selectinload(SecretVersion.key))
            .where(
                SecretVersion.secret_id == secret_id,
                SecretVersion.version == version,
            )
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_versions(self, secret_id: uuid.UUID) -> list[SecretVersion]:
        """List all versions of a secret, newest first."""
        stmt = (
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret_id)
            .order_by(SecretVersion.version.desc())
        )
        result = await self._db.execute(stmt)
        return result.scalars().all()

    async def deactivate_current(self, secret_id: uuid.UUID) -> None:
        """Mark all versions as not-current before creating a new current one."""
        await self._db.execute(
            update(SecretVersion)
            .where(
                SecretVersion.secret_id == secret_id,
                SecretVersion.is_current == True,  # noqa: E712
            )
            .values(is_current=False)
        )
