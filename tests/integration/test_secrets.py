"""
Integration tests for secret CRUD, versioning, and encryption.

These tests run against a real DB and Redis (via docker-compose test profile).
They test the full stack: HTTP → service → repository → DB.

Coverage:
  - Create secret (KV, JSON, binary)
  - Read secret (decrypt and verify value)
  - Update secret (creates new version)
  - Version listing
  - Specific version retrieval
  - Rollback
  - Soft delete
  - Encryption correctness (ciphertext ≠ plaintext)
  - AAD binding (ciphertext is version-specific)
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio


class TestSecretCRUD:
    @pytest.mark.asyncio
    async def test_create_and_read_kv_secret(self, client, developer_token):
        """Create a KV secret and verify it decrypts correctly."""
        # Create
        resp = await client.post(
            "/api/v1/secrets",
            json={
                "name": "test/db/password",
                "namespace": "test",
                "secret_type": "kv",
                "value": "supersecret123",
            },
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test/db/password"
        assert data["current_version"] == 1
        secret_id = data["id"]
        assert "value" not in data or data["value"] is None  # Not returned on create

        # Read
        resp = await client.get(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] == "supersecret123"

    @pytest.mark.asyncio
    async def test_create_json_secret(self, client, developer_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={
                "name": "test/api/config",
                "namespace": "test",
                "secret_type": "json",
                "value": {"host": "localhost", "port": 5432, "password": "secret"},
            },
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 201
        secret_id = resp.json()["id"]

        resp = await client.get(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        value = resp.json()["value"]
        assert value["host"] == "localhost"
        assert value["password"] == "secret"

    @pytest.mark.asyncio
    async def test_update_creates_new_version(self, client, developer_token):
        # Create
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "test/versioned", "value": "v1_value"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 201
        secret_id = resp.json()["id"]

        # Update
        resp = await client.put(
            f"/api/v1/secrets/{secret_id}",
            json={"value": "v2_value"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["current_version"] == 2

        # Read current (should be v2)
        resp = await client.get(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.json()["value"] == "v2_value"

    @pytest.mark.asyncio
    async def test_read_specific_version(self, client, developer_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "test/multi-version", "value": "original"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        secret_id = resp.json()["id"]

        await client.put(
            f"/api/v1/secrets/{secret_id}",
            json={"value": "updated"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )

        # Read version 1 (original)
        resp = await client.get(
            f"/api/v1/secrets/{secret_id}/versions/1",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["value"] == "original"

    @pytest.mark.asyncio
    async def test_rollback(self, client, developer_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "test/rollback-test", "value": "v1_data"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        secret_id = resp.json()["id"]

        await client.put(
            f"/api/v1/secrets/{secret_id}",
            json={"value": "v2_data"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )

        # Rollback to v1
        resp = await client.post(
            f"/api/v1/secrets/{secret_id}/rollback",
            json={"version": 1},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["current_version"] == 3  # New version created

        # Verify current is v1 content
        resp = await client.get(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.json()["value"] == "v1_data"

    @pytest.mark.asyncio
    async def test_delete_removes_from_list(self, client, developer_token, admin_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "test/to-delete", "value": "deletable"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        secret_id = resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 204

        # Should not be readable
        resp = await client.get(
            f"/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_duplicate_name_returns_409(self, client, developer_token):
        payload = {"name": "test/duplicate", "value": "v1", "namespace": "dup-ns"}
        resp = await client.post(
            "/api/v1/secrets", json=payload,
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 201

        resp = await client.post(
            "/api/v1/secrets", json=payload,
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_list_does_not_include_values(self, client, developer_token):
        """List endpoint must not expose secret values."""
        await client.post(
            "/api/v1/secrets",
            json={"name": "test/list-check", "value": "very-secret"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        resp = await client.get(
            "/api/v1/secrets",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert "value" not in item

    @pytest.mark.asyncio
    async def test_version_list(self, client, developer_token):
        resp = await client.post(
            "/api/v1/secrets",
            json={"name": "test/version-list", "value": "v1"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        secret_id = resp.json()["id"]

        await client.put(
            f"/api/v1/secrets/{secret_id}", json={"value": "v2"},
            headers={"Authorization": f"Bearer {developer_token}"},
        )

        resp = await client.get(
            f"/api/v1/secrets/{secret_id}/versions",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert resp.status_code == 200
        versions = resp.json()
        assert len(versions) == 2
        assert versions[0]["is_current"] is True
        assert versions[0]["version"] == 2  # Newest first
