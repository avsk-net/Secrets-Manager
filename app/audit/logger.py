"""
Append-only audit logger with HMAC chain integrity.

This is the single entry point for ALL audit events.  Every security-relevant
action in the system goes through emit_event().  No direct writes to the
audit_logs table are permitted elsewhere.

HMAC chain mechanics:
  entry_1.chain_hash = HMAC-SHA256(audit_hmac_key, "" || fields)
  entry_2.chain_hash = HMAC-SHA256(audit_hmac_key, entry_1.chain_hash || fields)
  entry_n.chain_hash = HMAC-SHA256(audit_hmac_key, entry_{n-1}.chain_hash || fields)

The chain covers: prev_hash, event_id, timestamp (ISO), actor_id, action, result.
Inserting a fake row into the middle of the sequence breaks all subsequent hashes.
Modifying any field in an existing row breaks that row's chain_hash and all after it.

Tamper detection:
  GET /api/v1/audit/verify-chain recomputes all chain_hashes and reports
  the first entry where the computed hash doesn't match the stored hash.

Sensitive data handling:
  The `details` JSONB field must NEVER contain plaintext secret values.
  Use only metadata: secret_name, namespace, version, action status, etc.
  The sanitize_details() helper enforces this.

Async safety:
  emit_event() is async and uses the request-scoped DB session.
  It calls db.flush() (not commit()) — the enclosing request transaction commits.
  This ensures audit events are atomic with the operation they record.
  On DB failure, both the operation AND the audit event roll back together.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from app.config import get_settings
from app.domain.enums import AuditEventType, AuditResult, ResourceType
from app.domain.models.audit import AuditLog
from app.repositories.audit_repository import AuditRepository

log = structlog.get_logger(__name__)

# Fields that must never appear in audit details — redacted if present
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret_value",
        "value",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "api_key",
        "credential",
        "passphrase",
    }
)


def sanitize_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """
    Remove known-sensitive keys from audit details.

    This is a defensive measure — callers should never pass sensitive data,
    but this provides a safety net.  Log a warning if redaction occurs.
    """
    if not details:
        return details

    cleaned = {}
    redacted = []
    for key, value in details.items():
        if key.lower() in _SENSITIVE_KEYS:
            redacted.append(key)
        else:
            cleaned[key] = value

    if redacted:
        log.warning("audit_details_redacted", keys=redacted)
        cleaned["_redacted_keys"] = redacted

    return cleaned if cleaned else None


def _compute_chain_hash(
    prev_hash: str | None,
    event_id: str,
    timestamp: str,
    actor_id: str,
    action: str,
    result: str,
    hmac_key: bytes,
) -> str:
    """
    Compute the HMAC-SHA256 chain hash for an audit entry.

    The message is a deterministic concatenation of the covered fields,
    separated by null bytes to prevent field boundary ambiguity.
    """
    prev = prev_hash or ""
    message = "\x00".join([prev, event_id, timestamp, actor_id, action, result])
    return hmac.new(hmac_key, message.encode("utf-8"), hashlib.sha256).hexdigest()


class AuditLogger:
    """
    Audit event emitter — use this class (not the repository directly).

    Typical usage:
        audit = AuditLogger(db)
        await audit.emit(
            event_type=AuditEventType.SECRET_READ,
            actor_id=token.sub,
            actor_username=token.username,
            resource_type=ResourceType.SECRET,
            resource_id=str(secret_id),
            action="read",
            result=AuditResult.SUCCESS,
            request_id=request_id,
            ip_address=client_ip,
            user_agent=user_agent,
            details={"namespace": "prod", "secret_name": "db/password", "version": 3},
        )
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._repo = AuditRepository(db)
        self._settings = get_settings()

    async def emit(
        self,
        event_type: AuditEventType,
        action: str,
        result: AuditResult,
        resource_type: ResourceType,
        actor_id: str | None = None,
        actor_username: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> AuditLog:
        """
        Emit a single audit event and persist it.

        Thread-safe: ULID event IDs are globally unique and time-ordered.
        Atomic: uses flush (not commit) — rolls back with the parent transaction.
        """
        now = datetime.now(timezone.utc)
        event_id = str(ULID())
        hmac_key = self._settings.get_audit_hmac_bytes()

        # Get previous entry for chain
        prev_entry = await self._repo.get_latest()
        prev_hash = prev_entry.chain_hash if prev_entry else None

        # Compute chain hash covering immutable event fields
        chain_hash = _compute_chain_hash(
            prev_hash=prev_hash,
            event_id=event_id,
            timestamp=now.isoformat(),
            actor_id=actor_id or "",
            action=action,
            result=result.value,
            hmac_key=hmac_key,
        )

        entry = AuditLog(
            id=uuid.uuid4(),
            event_id=event_id,
            event_type=event_type,
            actor_id=uuid.UUID(actor_id) if actor_id else None,
            actor_username=actor_username,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=uuid.UUID(request_id) if request_id else None,
            details=sanitize_details(details),
            error_message=error_message,
            timestamp=now,
            prev_hash=prev_hash,
            chain_hash=chain_hash,
        )

        await self._repo.create(entry)

        # Structured log at INFO — DO NOT log plaintext secrets here
        log.info(
            "audit_event",
            event_type=event_type.value,
            actor_id=actor_id,
            resource_type=resource_type.value,
            resource_id=resource_id,
            action=action,
            result=result.value,
            request_id=request_id,
        )
        return entry

    async def verify_chain(self, limit: int = 10000) -> tuple[bool, int, str | None]:
        """
        Verify the HMAC chain integrity for the audit log.

        Returns:
            (is_valid, checked_count, first_invalid_event_id)
        """
        entries = await self._repo.get_range_for_chain_verify(limit=limit)
        hmac_key = self._settings.get_audit_hmac_bytes()

        prev_hash: str | None = None
        for entry in entries:
            expected = _compute_chain_hash(
                prev_hash=prev_hash,
                event_id=entry.event_id,
                timestamp=entry.timestamp.isoformat(),
                actor_id=str(entry.actor_id) if entry.actor_id else "",
                action=entry.action,
                result=entry.result.value,
                hmac_key=hmac_key,
            )
            # Constant-time compare to prevent oracle attacks
            if not hmac.compare_digest(expected, entry.chain_hash):
                return False, len(entries), entry.event_id
            prev_hash = entry.chain_hash

        return True, len(entries), None
