"""
Security tests for RBAC permission enforcement.

These tests verify that every role has exactly the right access:
  - readonly cannot write or delete
  - developer cannot delete or manage users
  - admin cannot elevate to super_admin
  - Unauthenticated requests are rejected

These tests are critical for preventing privilege escalation bugs.
Each test documents the expected behavior, making it easy to spot
regressions when the permission matrix changes.
"""

from __future__ import annotations

import uuid

import pytest

from app.auth.jwt_handler import create_access_token
from app.domain.enums import UserRole


def _token(user_id: uuid.UUID, role: UserRole) -> str:
    token, _ = create_access_token(user_id=user_id, username="u", role=role)
    return token


@pytest.fixture
def readonly_token():
    return _token(uuid.uuid4(), UserRole.READONLY)


@pytest.fixture
def developer_token_fixture():
    return _token(uuid.uuid4(), UserRole.DEVELOPER)


@pytest.fixture
def admin_token_fixture():
    return _token(uuid.uuid4(), UserRole.ADMIN)


class TestUnauthenticated:
    """All endpoints require authentication."""

    @pytest.mark.asyncio
    async def test_list_secrets_unauthenticated(self, client):
        resp = await client.get("/api/v1/secrets")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_create_secret_unauthenticated(self, client):
        resp = await client.post("/api/v1/secrets", json={"name": "x", "value": "y"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_audit_log_unauthenticated(self, client):
        resp = await client.get("/api/v1/audit/logs")
        assert resp.status_code == 401


class TestReadonlyRole:
    """Readonly users can only read and list secrets."""

    @pytest.mark.asyncio
    async def test_readonly_can_list_secrets(self, client, readonly_token):
        resp = await client.get(
            "/api/v1/secrets",
            headers={"Authorization": f"Bearer {readonly_token}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_readonly_cannot_create_secret(self, client, readonly_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "x", "value": "y"},
            headers={"Authorization": f"Bearer {readonly_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_readonly_cannot_delete_secret(self, client, readonly_token, developer_token):
        # First create a secret with developer
        create_resp = await client.post(
            "/api/v1/secrets",
            json={"name": "perm-test/delete", "value": "v"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        secret_id = create_resp.json()["id"]

        # Readonly tries to delete
        resp = await client.delete(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {readonly_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_readonly_cannot_access_users(self, client, readonly_token):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {readonly_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_readonly_cannot_read_audit(self, client, readonly_token):
        resp = await client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {readonly_token}"},
        )
        assert resp.status_code == 403


class TestDeveloperRole:
    """Developers can read/write secrets but not delete or manage users."""

    @pytest.mark.asyncio
    async def test_developer_can_create_secret(self, client, developer_token_fixture):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "dev/create-test", "value": "val"},
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_developer_cannot_delete_secret(self, client, developer_token_fixture):
        create_resp = await client.post(
            "/api/v1/secrets",
            json={"name": "dev/delete-test", "value": "v"},
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        secret_id = create_resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_developer_cannot_list_users(self, client, developer_token_fixture):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_developer_cannot_read_audit(self, client, developer_token_fixture):
        resp = await client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        assert resp.status_code == 403


class TestAdminRole:
    """Admins can do everything except super_admin operations."""

    @pytest.mark.asyncio
    async def test_admin_can_delete_secret(self, client, admin_token_fixture, developer_token_fixture):
        create_resp = await client.post(
            "/api/v1/secrets",
            json={"name": "admin/delete-test", "value": "v"},
            headers={"Authorization": f"Bearer {developer_token_fixture}"},
        )
        secret_id = create_resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {admin_token_fixture}"},
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_admin_can_list_users(self, client, admin_token_fixture):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_token_fixture}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_cannot_create_super_admin(self, client, admin_token_fixture):
        """Privilege escalation: admin cannot create super_admin."""
        resp = await client.post(
            "/api/v1/users",
            json={
                "username": "escalated_admin",
                "email": "esc@test.com",
                "password": "Escalated!Pass123",
                "role": "super_admin",
            },
            headers={"Authorization": f"Bearer {admin_token_fixture}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_read_audit_logs(self, client, admin_token_fixture):
        resp = await client.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {admin_token_fixture}"},
        )
        assert resp.status_code == 200


class TestTokenSecurity:
    @pytest.mark.asyncio
    async def test_invalid_bearer_token_rejected(self, client):
        resp = await client.get(
            "/api/v1/secrets",
            headers={"Authorization": "Bearer invalidtoken"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix_rejected(self, client):
        token, _ = create_access_token(uuid.uuid4(), "u", UserRole.READONLY)
        resp = await client.get(
            "/api/v1/secrets",
            headers={"Authorization": token},  # No "Bearer " prefix
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unknown_scope_not_escalated(self, client):
        """A token with no valid scopes should not pass any scope checks."""
        from jose import jwt
        from app.config import get_settings
        s = get_settings()
        import time
        payload = {
            "sub": str(uuid.uuid4()), "username": "u",
            "role": "readonly", "scopes": ["invalid:scope"],
            "jti": str(uuid.uuid4()), "iat": int(time.time()),
            "exp": int(time.time()) + 900,
            "iss": s.jwt_issuer, "aud": s.jwt_audience,
        }
        token = jwt.encode(payload, s.jwt_secret_key, algorithm="HS256")
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "x", "value": "y"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
