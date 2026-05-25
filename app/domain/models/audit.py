"""
AuditLog model — tamper-resistant, append-only audit events.

Security guarantees:
1. Append-only: The application service layer NEVER issues UPDATE or DELETE
   against this table.  In production, the DB connection role used by the API
   should only have INSERT + SELECT privileges on audit_logs.
2. HMAC chain: each row's chain_hash covers the previous hash, event_id,
   timestamp, actor, action, and result.  Any tampering breaks the chain,
   detectable via /api/v1/audit/verify-chain.
3. Comprehensive metadata: IP (INET type for subnet range queries), user_agent,
   request_id for cross-log correlation, and a JSONB details blob for arbitrary
   event-specific context.
4. actor_username denormalized: preserves the identity string even if the User
   row is later deleted — forensic records must survive account deletion.

The prev_hash / chain_hash design is inspired by certificate transparency logs
and blockchain-style integrity proofs.  For maximum assurance, export the latest
chain_hash to an external immutable store (S3 object lock, transparency log).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin
from app.domain.enums import AuditEventType, AuditResult, ResourceType


class AuditLog(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "audit_logs"

    # Stable, lexicographically-sortable event identifier (ULID)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)

    event_type: Mapped[AuditEventType] = mapped_column(String(100), nullable=False)

    # actor_id may be NULL for pre-authentication events (e.g., failed login)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Denormalized username: survives actor account deletion
    actor_username: Mapped[str | None] = mapped_column(String(100), nullable=True)

    resource_type: Mapped[ResourceType] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    action: Mapped[str] = mapped_column(String(100), nullable=False)
    result: Mapped[AuditResult] = mapped_column(String(20), nullable=False)

    # Request metadata
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # Arbitrary event-specific context (e.g., {"secret_name": "...", "version": 3})
    # Sensitive values MUST be redacted before writing here — see audit/logger.py
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Authoritative timestamp — set by application (not DB server_default)
    # to ensure microsecond precision ordering across distributed nodes
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # ── HMAC chain ────────────────────────────────────────────────────────────
    # prev_hash: chain_hash of the immediately preceding audit row (NULL for row #1)
    # chain_hash: HMAC-SHA256(audit_hmac_key, prev_hash || event fields...)
    # Any modification to a row, or insertion of a row into the middle of the
    # sequence, breaks all chain_hash values from that point forward.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_audit_logs_event_type", "event_type"),
        Index("ix_audit_logs_timestamp", "timestamp"),
        Index("ix_audit_logs_actor_ts", "actor_id", "timestamp"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_result", "result"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog event_id={self.event_id!r} "
            f"type={self.event_type} result={self.result}>"
        )
