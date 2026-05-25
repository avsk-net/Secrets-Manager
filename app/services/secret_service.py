"""
Secret management service — create, read, update, delete, and version secrets.

Encryption flow for WRITE:
  1. Get or create a DEK for this secret (KeyManagementService)
  2. Serialize the plaintext value to bytes
  3. Build AAD: "{secret_id}:{version}" (binds ciphertext to its identity)
  4. Encrypt with AES-256-GCM using the DEK + random nonce
  5. Compute HMAC-SHA256 checksum of plaintext (for integrity verification)
  6. Store: (encrypted_value, nonce, key_id, checksum) in SecretVersion
  7. Emit SECRET_CREATE or SECRET_UPDATE audit event

Decryption flow for READ:
  1. Load SecretVersion with eagerly-loaded KeyMetadata
  2. Unwrap DEK from KeyMetadata using MEK (KeyManagementService)
  3. Rebuild AAD: "{secret_id}:{version}"
  4. Decrypt: AES-GCM raises InvalidTag if anything was tampered
  5. Verify checksum (HMAC of plaintext vs stored)
  6. Deserialize bytes back to the original type (str/dict/bytes)
  7. Emit SECRET_READ audit event
  8. Zero-fill the DEK from memory

Cache invalidation:
  After any write, the cached copy of the secret (if any) is invalidated
  from Redis immediately.  Reads check the cache before hitting the DB.
  Cache TTL is configured via SECRET_CACHE_TTL_SECONDS.

The plaintext value NEVER appears in:
  - Database (only ciphertext)
  - Logs (structlog redacts it)
  - Audit details (only metadata: name, namespace, version)
  - Error messages
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from cryptography.exceptions import InvalidTag
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.config import get_settings
from app.crypto.engine import (
    EncryptedBlob,
    build_aad,
    compute_checksum,
    decrypt,
    encrypt,
    verify_checksum,
)
from app.crypto.key_management import KeyManagementService
from app.domain.enums import AuditEventType, AuditResult, ResourceType, SecretType
from app.domain.models.secret import Secret, SecretVersion
from app.domain.schemas.secret import (
    SecretCreate,
    SecretListResponse,
    SecretResponse,
    SecretUpdate,
    SecretVersionResponse,
)
from app.repositories.secret_repository import SecretRepository, SecretVersionRepository


class SecretNotFoundError(Exception):
    pass


class SecretAlreadyExistsError(Exception):
    pass


class SecretDecryptionError(Exception):
    """Wraps cryptography failures — do NOT include plaintext in message."""
    pass


class SecretService:
    def __init__(
        self,
        db: AsyncSession,
        redis_client: aioredis.Redis,
    ) -> None:
        self._db = db
        self._redis = redis_client
        self._settings = get_settings()
        self._secret_repo = SecretRepository(db)
        self._version_repo = SecretVersionRepository(db)
        self._key_svc = KeyManagementService(db, redis_client)
        self._audit = AuditLogger(db)

    # ── Create ────────────────────────────────────────────────────────────────

    async def create_secret(
        self,
        payload: SecretCreate,
        actor_id: str,
        actor_username: str,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SecretResponse:
        """Create a new secret and encrypt its initial value."""
        # Check for existing secret with same name/namespace
        if await self._secret_repo.name_exists(payload.name, payload.namespace):
            raise SecretAlreadyExistsError(
                f"Secret '{payload.name}' already exists in namespace '{payload.namespace}'"
            )

        actor_uuid = uuid.UUID(actor_id)
        now = datetime.now(timezone.utc)

        # Create the Secret record (no value stored here)
        secret = Secret(
            id=uuid.uuid4(),
            name=payload.name,
            namespace=payload.namespace,
            secret_type=payload.secret_type,
            description=payload.description,
            created_by_id=actor_uuid,
            current_version=0,
            created_at=now,
            updated_at=now,
        )
        await self._secret_repo.create(secret)

        # Encrypt and create version 1
        version = await self._create_version(
            secret=secret,
            value=payload.value,
            version_number=1,
            actor_id=actor_uuid,
            metadata=payload.metadata,
        )

        # Update the secret's current_version pointer
        secret.current_version = 1

        await self._audit.emit(
            event_type=AuditEventType.SECRET_CREATE,
            action="create",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(secret.id),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "secret_name": payload.name,
                "namespace": payload.namespace,
                "secret_type": payload.secret_type.value,
            },
        )

        return SecretResponse(
            id=secret.id,
            name=secret.name,
            namespace=secret.namespace,
            secret_type=secret.secret_type,
            description=secret.description,
            current_version=1,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            created_by_id=secret.created_by_id,
            version_id=version.id,
        )

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_secret(
        self,
        secret_id: uuid.UUID,
        actor_id: str,
        actor_username: str,
        version: int | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SecretResponse:
        """Read and decrypt a secret (latest or specific version)."""
        secret = await self._secret_repo.get(secret_id)
        if not secret or secret.is_deleted:
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        # Cache check (only for current version requests)
        if version is None and self._settings.secret_cache_enabled:
            cached = await self._get_from_cache(str(secret_id))
            if cached:
                # Still emit audit event for cache hits — all reads must be logged
                await self._emit_read_audit(
                    secret, actor_id, actor_username, request_id, ip_address, user_agent,
                    version_num=secret.current_version, from_cache=True
                )
                return cached

        # Load the version
        if version is None:
            sv = await self._version_repo.get_current_version(secret_id)
        else:
            sv = await self._version_repo.get_version(secret_id, version)

        if not sv:
            raise SecretNotFoundError(f"Version {version} not found for secret {secret_id}")

        # Decrypt
        plaintext = await self._decrypt_version(secret, sv)

        await self._emit_read_audit(
            secret, actor_id, actor_username, request_id, ip_address, user_agent,
            version_num=sv.version, from_cache=False
        )

        response = SecretResponse(
            id=secret.id,
            name=secret.name,
            namespace=secret.namespace,
            secret_type=secret.secret_type,
            description=secret.description,
            current_version=secret.current_version,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            created_by_id=secret.created_by_id,
            value=self._deserialize_value(plaintext, secret.secret_type),
            version_id=sv.id,
        )

        # Cache the result (brief TTL)
        if version is None and self._settings.secret_cache_enabled:
            await self._put_in_cache(str(secret_id), response)

        return response

    # ── Update (creates new version) ─────────────────────────────────────────

    async def update_secret(
        self,
        secret_id: uuid.UUID,
        payload: SecretUpdate,
        actor_id: str,
        actor_username: str,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SecretResponse:
        """Update a secret — creates a new immutable version."""
        secret = await self._secret_repo.get(secret_id)
        if not secret or secret.is_deleted:
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        actor_uuid = uuid.UUID(actor_id)
        new_version_number = secret.current_version + 1

        # Deactivate current version
        await self._version_repo.deactivate_current(secret_id)

        # Encrypt new version
        version = await self._create_version(
            secret=secret,
            value=payload.value,
            version_number=new_version_number,
            actor_id=actor_uuid,
            metadata=payload.metadata,
        )

        secret.current_version = new_version_number
        if payload.description is not None:
            secret.description = payload.description

        # Invalidate cache
        await self._invalidate_cache(str(secret_id))

        await self._audit.emit(
            event_type=AuditEventType.SECRET_UPDATE,
            action="update",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(secret.id),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "secret_name": secret.name,
                "namespace": secret.namespace,
                "new_version": new_version_number,
            },
        )

        return SecretResponse(
            id=secret.id,
            name=secret.name,
            namespace=secret.namespace,
            secret_type=secret.secret_type,
            description=secret.description,
            current_version=new_version_number,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            created_by_id=secret.created_by_id,
            version_id=version.id,
        )

    # ── Delete ────────────────────────────────────────────────────────────────

    async def delete_secret(
        self,
        secret_id: uuid.UUID,
        actor_id: str,
        actor_username: str,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Soft-delete a secret (recoverable by super_admin within retention window)."""
        deleted = await self._secret_repo.soft_delete(secret_id, uuid.UUID(actor_id))
        if not deleted:
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        await self._invalidate_cache(str(secret_id))

        await self._audit.emit(
            event_type=AuditEventType.SECRET_DELETE,
            action="delete",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(secret_id),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    # ── List ──────────────────────────────────────────────────────────────────

    async def list_secrets(
        self,
        namespace: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> SecretListResponse:
        from app.domain.schemas.secret import SecretListItem
        secrets, total = await self._secret_repo.list_secrets(
            namespace=namespace, page=page, page_size=page_size
        )
        return SecretListResponse(
            items=[
                SecretListItem(
                    id=s.id, name=s.name, namespace=s.namespace,
                    secret_type=s.secret_type, description=s.description,
                    current_version=s.current_version,
                    created_at=s.created_at, updated_at=s.updated_at,
                )
                for s in secrets
            ],
            total=total,
            page=page,
            page_size=page_size,
        )

    # ── Rollback ──────────────────────────────────────────────────────────────

    async def rollback_to_version(
        self,
        secret_id: uuid.UUID,
        target_version: int,
        actor_id: str,
        actor_username: str,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SecretResponse:
        """
        Roll back to a previous version.

        Implementation: creates a NEW version that is a copy of the target
        version's ciphertext (re-encrypted with a fresh nonce).  This preserves
        the audit trail — we can see "rolled back from v5 to content of v2".
        The old versions are retained (immutable history).
        """
        secret = await self._secret_repo.get(secret_id)
        if not secret or secret.is_deleted:
            raise SecretNotFoundError(f"Secret {secret_id} not found")

        target_sv = await self._version_repo.get_version(secret_id, target_version)
        if not target_sv:
            raise SecretNotFoundError(f"Version {target_version} not found")

        # Decrypt the target version
        plaintext = await self._decrypt_version(secret, target_sv)

        # Create a new version with the same content
        actor_uuid = uuid.UUID(actor_id)
        new_version_number = secret.current_version + 1
        await self._version_repo.deactivate_current(secret_id)

        await self._create_version(
            secret=secret,
            value=self._deserialize_value(plaintext, secret.secret_type),
            version_number=new_version_number,
            actor_id=actor_uuid,
            metadata=target_sv.metadata_,
        )
        secret.current_version = new_version_number
        await self._invalidate_cache(str(secret_id))

        await self._audit.emit(
            event_type=AuditEventType.SECRET_ROLLBACK,
            action="rollback",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(secret_id),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "secret_name": secret.name,
                "rolled_back_to_version": target_version,
                "new_version": new_version_number,
            },
        )

        return SecretResponse(
            id=secret.id, name=secret.name, namespace=secret.namespace,
            secret_type=secret.secret_type, description=secret.description,
            current_version=new_version_number,
            created_at=secret.created_at, updated_at=secret.updated_at,
            created_by_id=secret.created_by_id,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _create_version(
        self,
        secret: Secret,
        value: Any,
        version_number: int,
        actor_id: uuid.UUID,
        metadata: dict | None = None,
    ) -> SecretVersion:
        """Serialize, encrypt, and persist a new secret version."""
        plaintext = self._serialize_value(value, secret.secret_type)

        # Get or create the DEK for this secret
        key_metadata = await self._key_svc.get_active_key_for_secret(secret.id)

        # Use the unwrapped DEK for encryption
        dek = await self._key_svc.get_dek(key_metadata)
        try:
            aad = build_aad(str(secret.id), version_number)
            blob: EncryptedBlob = encrypt(plaintext, dek, aad)

            # HMAC of plaintext using DEK as the HMAC key
            # This ties the checksum to the encryption key — compromising one
            # doesn't help verify the other without the key
            checksum = compute_checksum(plaintext, dek)
        finally:
            # Best-effort memory wipe
            dek = b"\x00" * len(dek)  # noqa: F841
            del dek

        sv = SecretVersion(
            id=uuid.uuid4(),
            secret_id=secret.id,
            version=version_number,
            encrypted_value=blob.ciphertext,
            nonce=blob.nonce,
            key_id=key_metadata.id,
            checksum=checksum,
            metadata_=metadata,
            created_by_id=actor_id,
            created_at=datetime.now(timezone.utc),
            is_current=True,
        )
        await self._version_repo.create(sv)
        return sv

    async def _decrypt_version(self, secret: Secret, sv: SecretVersion) -> bytes:
        """Decrypt a SecretVersion and verify integrity."""
        key_metadata = sv.key
        if key_metadata is None:
            key_metadata = await self._key_svc.get_key_by_id(sv.key_id)
            if not key_metadata:
                raise SecretDecryptionError("Key metadata not found")

        dek = await self._key_svc.get_dek(key_metadata)
        try:
            aad = build_aad(str(secret.id), sv.version)
            try:
                plaintext = decrypt(sv.encrypted_value, dek, sv.nonce, aad)
            except InvalidTag as exc:
                raise SecretDecryptionError(
                    "Decryption authentication failed — data may be corrupted"
                ) from exc

            # Verify checksum (constant-time)
            if not verify_checksum(plaintext, sv.checksum, dek):
                raise SecretDecryptionError("Checksum verification failed")

        finally:
            dek = b"\x00" * len(dek)  # noqa: F841
            del dek

        return plaintext

    def _serialize_value(self, value: Any, secret_type: SecretType) -> bytes:
        """Serialize a secret value to bytes for encryption."""
        if secret_type == SecretType.KV:
            return str(value).encode("utf-8")
        elif secret_type == SecretType.JSON:
            return json.dumps(value, separators=(",", ":")).encode("utf-8")
        elif secret_type == SecretType.BINARY:
            if isinstance(value, bytes):
                return value
            # Accept base64 strings for BINARY type
            return base64.b64decode(value)
        else:
            return str(value).encode("utf-8")

    def _deserialize_value(self, plaintext: bytes, secret_type: SecretType) -> Any:
        """Deserialize decrypted bytes back to the appropriate type."""
        if secret_type == SecretType.KV:
            return plaintext.decode("utf-8")
        elif secret_type == SecretType.JSON:
            return json.loads(plaintext.decode("utf-8"))
        elif secret_type == SecretType.BINARY:
            return base64.b64encode(plaintext).decode("ascii")
        return plaintext.decode("utf-8", errors="replace")

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _cache_key(self, secret_id: str) -> str:
        return f"secret:cache:{secret_id}"

    async def _get_from_cache(self, secret_id: str) -> SecretResponse | None:
        data = await self._redis.get(self._cache_key(secret_id))
        if data:
            return SecretResponse.model_validate_json(data)
        return None

    async def _put_in_cache(self, secret_id: str, response: SecretResponse) -> None:
        await self._redis.setex(
            self._cache_key(secret_id),
            self._settings.secret_cache_ttl_seconds,
            response.model_dump_json(),
        )

    async def _invalidate_cache(self, secret_id: str) -> None:
        await self._redis.delete(self._cache_key(secret_id))

    async def _emit_read_audit(
        self, secret: Secret, actor_id: str, actor_username: str,
        request_id: str | None, ip_address: str | None, user_agent: str | None,
        version_num: int, from_cache: bool,
    ) -> None:
        await self._audit.emit(
            event_type=AuditEventType.SECRET_READ,
            action="read",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.SECRET,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(secret.id),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "secret_name": secret.name,
                "namespace": secret.namespace,
                "version": version_num,
                "from_cache": from_cache,
            },
        )
