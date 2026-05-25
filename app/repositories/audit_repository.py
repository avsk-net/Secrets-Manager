"""
Audit log repository — strictly append-only.

This repository intentionally provides NO update or delete methods.
The only permitted operations are:
  - create (INSERT a new audit event)
  - get (SELECT by ID)
  - list (SELECT with filters)
  - get_latest (SELECT most recent entry — for chain building)

In production, the DB user for the API connection should have:
  GRANT SELECT, INSERT ON audit_logs TO api_user;
  -- No UPDATE, DELETE, TRUNCATE
This provides DB-level enforcement of append-only semantics.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import AuditEventType, AuditResult, ResourceType
from app.domain.models.audit import AuditLog
from app.repositories.base import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    model = AuditLog

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    # Explicitly block update/delete at the repository level
    async def delete(self, obj: AuditLog) -> None:  # type: ignore[override]
        raise NotImplementedError("Audit logs are append-only and cannot be deleted")

    async def get_latest(self) -> AuditLog | None:
        """Return the most recent audit entry for HMAC chain building."""
        stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(1)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_events(
        self,
        event_type: AuditEventType | None = None,
        actor_id: uuid.UUID | None = None,
        resource_type: ResourceType | None = None,
        resource_id: str | None = None,
        result_filter: AuditResult | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AuditLog], int]:
        conditions = []
        if event_type:
            conditions.append(AuditLog.event_type == event_type)
        if actor_id:
            conditions.append(AuditLog.actor_id == actor_id)
        if resource_type:
            conditions.append(AuditLog.resource_type == resource_type)
        if resource_id:
            conditions.append(AuditLog.resource_id == resource_id)
        if result_filter:
            conditions.append(AuditLog.result == result_filter)
        if from_ts:
            conditions.append(AuditLog.timestamp >= from_ts)
        if to_ts:
            conditions.append(AuditLog.timestamp <= to_ts)

        # Count query
        count_stmt = select(func.count()).select_from(AuditLog)
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        count_result = await self._db.execute(count_stmt)
        total = count_result.scalar_one()

        # Data query
        stmt = select(AuditLog)
        if conditions:
            stmt = stmt.where(*conditions)
        stmt = (
            stmt.order_by(AuditLog.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        data_result = await self._db.execute(stmt)
        return data_result.scalars().all(), total

    async def get_range_for_chain_verify(
        self,
        limit: int = 10000,
    ) -> list[AuditLog]:
        """Load audit entries in insertion order for chain verification."""
        stmt = (
            select(AuditLog)
            .order_by(AuditLog.timestamp.asc())
            .limit(limit)
        )
        result = await self._db.execute(stmt)
        return result.scalars().all()
