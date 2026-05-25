"""
Pydantic v2 schemas for secret management endpoints.

Critical: these schemas represent DECRYPTED secret data in transit.
They must NEVER be logged, cached, or persisted anywhere after the
response has been sent to the client.

The `value` field is the plaintext secret — it exists only in:
  1. The API response body (TLS-encrypted in transit)
  2. RAM during the request lifecycle
It never touches disk, database, or logs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.domain.enums import SecretType


class SecretCreate(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=500,
        pattern=r"^[a-zA-Z0-9_\-./]+$",  # Path-safe characters only
        description="Secret name, e.g. 'prod/db/password'",
    )
    namespace: str = Field(
        default="default",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9_\-]+$",
    )
    secret_type: SecretType = SecretType.KV
    value: str | dict[str, Any] | bytes = Field(
        ...,
        description="Plaintext secret value — encrypted before storage",
    )
    description: str | None = Field(default=None, max_length=1000)
    metadata: dict[str, str] | None = None

    model_config = {"extra": "forbid"}


class SecretUpdate(BaseModel):
    value: str | dict[str, Any] | bytes = Field(
        ...,
        description="New plaintext value — creates a new version",
    )
    description: str | None = Field(default=None, max_length=1000)
    metadata: dict[str, str] | None = None

    model_config = {"extra": "forbid"}


class SecretVersionResponse(BaseModel):
    """Version metadata — never includes the plaintext value by default."""

    id: uuid.UUID
    secret_id: uuid.UUID
    version: int
    is_current: bool
    created_at: datetime
    created_by_id: uuid.UUID | None
    metadata: dict | None

    model_config = {"from_attributes": True}


class SecretResponse(BaseModel):
    """
    Full secret response including decrypted value.

    WARNING: This schema carries plaintext. Only return this from
    explicit read endpoints, never in list responses.
    """

    id: uuid.UUID
    name: str
    namespace: str
    secret_type: SecretType
    description: str | None
    current_version: int
    created_at: datetime
    updated_at: datetime
    created_by_id: uuid.UUID | None
    # The decrypted value — present only on explicit read
    value: str | dict[str, Any] | None = None
    version_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class SecretListItem(BaseModel):
    """List view — no value, just metadata."""

    id: uuid.UUID
    name: str
    namespace: str
    secret_type: SecretType
    description: str | None
    current_version: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SecretListResponse(BaseModel):
    items: list[SecretListItem]
    total: int
    page: int
    page_size: int


class RollbackRequest(BaseModel):
    version: int = Field(..., ge=1, description="Version number to rollback to")

    model_config = {"extra": "forbid"}
