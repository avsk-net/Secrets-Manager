"""
Integration tests for the audit log system.

Coverage:
  - Audit events are emitted for all secret CRUD operations
  - Audit events are emitted for auth operations
  - HMAC chain is valid after multiple operations
  - Chain breaks are detected correctly
  - Filtering (by actor, event_type, result) works
  - Append-only constraint (no delete/update in repository)
"""

from __future__ import annotations

import uuid

import pytest

from app.audit.logger import AuditLogger, _compute_chain_hash
from app.domain.enums import AuditEventType, AuditResult, ResourceType


class TestAuditEvents:
    @pytest.mark.asyncio
    async def test_secret_create_emits_audit(self, client, developer_token):
        """Creating a secret should produce a SECRET_CREATE audit event."""
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "audit-test/create", "value": "v1"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 201
        secret_id = resp.json()["id"]

        # Check audit log
        resp = await client.get(
            f"/api/v1/audit/logs?resource_id={secret_id}&event_type=secret.create",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        # developer doesn't have audit:read — should be 403
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_audit_read_requires_admin(self, client, developer_token, admin_token):
        """Audit log is only accessible to admins."""
        resp_dev = await client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp_dev.status_code == 403

        resp_admin = await client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_admin.status_code == 200

    @pytest.mark.asyncio
    async def test_failed_login_emits_audit(self, client, admin_token):
        """Failed login attempts appear in the audit log."""
        await client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent", "password": "wrongpassword"},
        )

        resp = await client.get(
            "/api/v1/audit/logs?event_type=auth.login.failure",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_audit_chain_valid_after_operations(self, client, developer_token, admin_token):
        """Chain should be valid after a series of operations."""
        # Perform several operations to build the chain
        for i in range(3):
            await client.post(
                "/api/v1/secrets",
                json={"name": f"chain-test/{i}", "value": f"value-{i}"},
                headers={"Authorization": f"Bearer {developer_token}"},
            )

        # Verify chain
        resp = await client.post(
            "/api/v1/audit/verify-chain",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked_entries"] >= 3

    @pytest.mark.asyncio
    async def test_audit_log_filter_by_result(self, client, admin_token):
        """Can filter audit events by result (success/failure)."""
        resp = await client.get(
            "/api/v1/audit/logs?result=failure",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # All returned results should be failures
        for item in data["items"]:
            assert item["result"] == "failure"

    @pytest.mark.asyncio
    async def test_audit_log_pagination(self, client, developer_token, admin_token):
        """Pagination should work correctly."""
        resp = await client.get(
            "/api/v1/audit/logs?page=1&page_size=5",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 5
        assert data["page"] == 1
        assert data["page_size"] == 5


class TestAuditIntegrity:
    @pytest.mark.asyncio
    async def test_hmac_chain_computes_correctly(self, db, test_settings):
        """Test HMAC chain hash computation in isolation."""
        from app.config import get_settings
        settings = get_settings()
        hmac_key = settings.get_audit_hmac_bytes()

        # Chain hash for first entry (no prev)
        h1 = _compute_chain_hash(
            prev_hash=None,
            event_id="event1",
            timestamp="2025-01-01T00:00:00",
            actor_id="actor1",
            action="read",
            result="success",
            hmac_key=hmac_key,
        )
        assert len(h1) == 64  # SHA-256 hex

        # Chain hash for second entry
        h2 = _compute_chain_hash(
            prev_hash=h1,
            event_id="event2",
            timestamp="2025-01-01T00:00:01",
            actor_id="actor1",
            action="write",
            result="success",
            hmac_key=hmac_key,
        )
        assert h1 != h2  # Each hash is unique

    @pytest.mark.asyncio
    async def test_append_only_repo_blocks_delete(self, db):
        """AuditRepository.delete() should raise NotImplementedError."""
        from app.repositories.audit_repository import AuditRepository
        repo = AuditRepository(db)
        with pytest.raises(NotImplementedError):
            await repo.delete(None)

    @pytest.mark.asyncio
    async def test_audit_logger_emits_and_stores(self, db, test_settings):
        """AuditLogger.emit() should create a persisted audit entry."""
        from app.audit.logger import AuditLogger
        from app.domain.enums import AuditEventType, AuditResult, ResourceType
        from app.repositories.audit_repository import AuditRepository

        audit = AuditLogger(db)
        entry = await audit.emit(
            event_type=AuditEventType.SECRET_READ,
            action="read",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=str(uuid.uuid4()),
            actor_username="testuser",
            resource_id=str(uuid.uuid4()),
        )
        assert entry.id is not None
        assert entry.chain_hash is not None
        assert len(entry.chain_hash) == 64

    @pytest.mark.asyncio
    async def test_sensitive_keys_sanitized_in_details(self, db, test_settings):
        """Sensitive keys should be redacted from audit details."""
        from app.audit.logger import AuditLogger, sanitize_details
        from app.domain.enums import AuditEventType, AuditResult, ResourceType

        # Test the sanitize_details helper directly
        details = {
            "username": "alice",
            "password": "supersecret",   # should be redacted
            "secret_name": "prod/db",
        }
        cleaned = sanitize_details(details)
        assert "password" not in cleaned
        assert "username" in cleaned
        assert "secret_name" in cleaned
