"""
Audit log endpoints — read-only access for compliance and forensics.

Endpoint summary:
  GET  /audit/logs              — Query audit events with filters
  GET  /audit/logs/{event_id}   — Get a specific audit event
  POST /audit/verify-chain      — Verify HMAC chain integrity

Authorization:
  All endpoints require audit:read scope (admin+ by default).
  verify-chain requires audit:verify scope (also admin+).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.auth.dependencies import require_scope
from app.db.session import get_db
from app.domain.enums import AuditEventType, AuditResult, ResourceType, Scope
from app.domain.schemas.audit import (
    AuditLogListResponse,
    AuditLogResponse,
    ChainVerifyResponse,
)
from app.repositories.audit_repository import AuditRepository
from datetime import datetime

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
    summary="Query audit log events",
)
async def list_audit_logs(
    event_type: AuditEventType | None = None,
    actor_id: uuid.UUID | None = None,
    resource_type: ResourceType | None = None,
    resource_id: str | None = None,
    result: AuditResult | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """
    Query audit log events with filtering.

    The audit log is append-only — entries are never modified or deleted.
    Results are ordered by timestamp descending (most recent first).
    """
    repo = AuditRepository(db)
    events, total = await repo.list_events(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        result_filter=result,
        from_ts=from_ts,
        to_ts=to_ts,
        page=page,
        page_size=page_size,
    )
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/logs/{event_id}",
    response_model=AuditLogResponse,
    dependencies=[Depends(require_scope(Scope.AUDIT_READ))],
    summary="Get a specific audit event by event_id",
)
async def get_audit_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
) -> AuditLogResponse:
    from sqlalchemy import select
    from app.domain.models.audit import AuditLog
    stmt = select(AuditLog).where(AuditLog.event_id == event_id)
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit event not found")
    return AuditLogResponse.model_validate(entry)


@router.post(
    "/verify-chain",
    response_model=ChainVerifyResponse,
    dependencies=[Depends(require_scope(Scope.AUDIT_VERIFY))],
    summary="Verify audit log HMAC chain integrity",
)
async def verify_chain(
    db: AsyncSession = Depends(get_db),
) -> ChainVerifyResponse:
    """
    Verify the HMAC chain integrity of the audit log.

    Recomputes chain_hash for each entry and compares against stored values.
    Any tampering (modification, insertion, deletion) will break the chain.

    Returns the first invalid event_id if tampering is detected.
    This endpoint is itself audited (even verify calls are logged).
    """
    audit = AuditLogger(db)
    is_valid, count, first_invalid = await audit.verify_chain()
    return ChainVerifyResponse(
        valid=is_valid,
        checked_entries=count,
        first_invalid_event_id=first_invalid,
        message=(
            f"Chain valid across {count} entries"
            if is_valid
            else f"Chain broken at event {first_invalid!r}"
        ),
    )
