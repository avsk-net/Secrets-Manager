"""Pydantic v2 schemas for audit log endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.domain.enums import AuditEventType, AuditResult, ResourceType


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    event_id: str
    event_type: AuditEventType
    actor_id: uuid.UUID | None
    actor_username: str | None
    resource_type: ResourceType
    resource_id: str | None
    action: str
    result: AuditResult
    ip_address: str | None
    user_agent: str | None
    request_id: uuid.UUID | None
    details: dict | None
    error_message: str | None
    timestamp: datetime
    prev_hash: str | None
    chain_hash: str

    model_config = {"from_attributes": True}


class AuditLogFilter(BaseModel):
    event_type: AuditEventType | None = None
    actor_id: uuid.UUID | None = None
    resource_type: ResourceType | None = None
    resource_id: str | None = None
    result: AuditResult | None = None
    from_ts: datetime | None = None
    to_ts: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)

    model_config = {"extra": "forbid"}


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


class ChainVerifyResponse(BaseModel):
    valid: bool
    checked_entries: int
    first_invalid_event_id: str | None = None
    message: str
