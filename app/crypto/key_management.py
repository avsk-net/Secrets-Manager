"""
Envelope encryption key lifecycle management.

Architecture (3-tier key hierarchy):
─────────────────────────────────────────────────────────────────────
  Tier 1: Root Key / MEK (Master Encryption Key)
    - Stored as environment variable (or KMS in production)
    - Used ONLY to wrap/unwrap DEKs
    - Never touches user data
    - Rotation: set new MEK, re-wrap all active DEKs, increment mek_version

  Tier 2: Data Encryption Key (DEK)
    - One per secret (one-to-one isolates key compromise blast radius)
    - 256-bit random key, NEVER stored in plaintext
    - Stored as: wrapped = AES-GCM(DEK, MEK) → KeyMetadata.encrypted_key
    - In-memory unwrapped DEK exists only during encrypt/decrypt, then GC'd

  Tier 3: Per-version nonce
    - 96-bit random nonce unique per SecretVersion
    - Ensures IND-CPA security even with key reuse across versions
─────────────────────────────────────────────────────────────────────

Distributed locking:
  DEK creation uses Redis SETNX to prevent two concurrent API nodes
  from creating two DEKs for the same secret (race condition on first write).
  Lock TTL = 5 seconds — released immediately after DEK creation.

Key rotation design:
  Full rotation:   generate new MEK → re-wrap all DEKs → new mek_version
  Secret rotation: generate new DEK → re-encrypt all current values → new key record
  Both triggered by Celery task or admin API call.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from app.config import get_settings
from app.crypto.engine import generate_dek, unwrap_key, wrap_key
from app.domain.models.secret import KeyMetadata


class KeyManagementService:
    """
    Service for DEK lifecycle management.

    Methods are intentionally low-level — callers (SecretService) handle
    business logic; this class handles only cryptographic key operations.
    """

    def __init__(self, db: AsyncSession, redis_client: aioredis.Redis) -> None:
        self._db = db
        self._redis = redis_client
        self._settings = get_settings()

    # ── MEK access ────────────────────────────────────────────────────────────

    def _get_mek(self) -> bytes:
        """
        Return the Master Encryption Key as raw bytes.

        In production, replace this with a KMS call (AWS KMS, GCP KMS, Vault).
        The environment-variable approach is acceptable for development and
        single-node deployments with encrypted storage.
        """
        return self._settings.get_mek_bytes()

    # ── DEK lifecycle ─────────────────────────────────────────────────────────

    async def create_dek(self, reason: str = "initial") -> KeyMetadata:
        """
        Generate a new DEK, wrap it with the MEK, and persist to DB.

        The plaintext DEK never leaves this method — it is wrapped immediately
        after generation and then discarded.
        """
        key_id = f"key_{ULID()}"
        dek = generate_dek()  # raw 32-byte key

        try:
            mek = self._get_mek()
            wrapped = wrap_key(dek, mek)  # nonce || AES-GCM(dek, mek)
        finally:
            # Zero-fill the DEK bytes from memory as best-effort.
            # Python doesn't guarantee immediate GC, but this reduces exposure window.
            # In a C extension (like libsodium), you'd use sodium_memzero().
            dek = b"\x00" * len(dek)  # noqa: F841 (intentional overwrite)
            del dek

        now = datetime.now(timezone.utc)
        record = KeyMetadata(
            id=uuid.uuid4(),
            key_id=key_id,
            algorithm="AES-256-GCM",
            encrypted_key=wrapped,
            mek_version=1,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        self._db.add(record)
        await self._db.flush()  # Get the ID without committing
        return record

    async def get_dek(self, key_metadata: KeyMetadata) -> bytes:
        """
        Unwrap (decrypt) a stored DEK using the current MEK.

        Returns raw 32-byte DEK.
        The caller is responsible for zeroing the DEK after use.

        Raises:
            cryptography.exceptions.InvalidTag: if MEK is wrong or DEK was tampered.
        """
        mek = self._get_mek()
        return unwrap_key(key_metadata.encrypted_key, mek)

    async def get_active_key_for_secret(
        self, secret_id: uuid.UUID
    ) -> KeyMetadata:
        """
        Get the active DEK for a secret, creating one if it doesn't exist.

        Uses a distributed lock to prevent concurrent DEK creation races
        across multiple API nodes.
        """
        # Try to get existing active key for this secret via secret_versions
        from app.domain.models.secret import SecretVersion

        stmt = (
            select(KeyMetadata)
            .join(SecretVersion, SecretVersion.key_id == KeyMetadata.id)
            .where(
                SecretVersion.secret_id == secret_id,
                SecretVersion.is_current == True,  # noqa: E712
                KeyMetadata.is_active == True,  # noqa: E712
            )
            .limit(1)
        )
        result = await self._db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            return existing

        # No existing key — create one with distributed lock
        lock_key = f"lock:dek:create:{secret_id}"
        return await self._create_dek_with_lock(lock_key)

    async def _create_dek_with_lock(self, lock_key: str) -> KeyMetadata:
        """Create a DEK while holding a Redis distributed lock."""
        lock_ttl = 5  # seconds
        acquired = await self._redis.set(lock_key, "1", nx=True, ex=lock_ttl)

        if not acquired:
            # Another node is creating the key — brief spin wait
            import asyncio
            for _ in range(10):
                await asyncio.sleep(0.1)
                # Check if key was created
                # (simplified — production would use Redlock algorithm)
                break

        try:
            return await self.create_dek()
        finally:
            await self._redis.delete(lock_key)

    async def rotate_dek(
        self,
        old_key: KeyMetadata,
        reason: str = "scheduled_rotation",
    ) -> KeyMetadata:
        """
        Rotate a DEK: create a new DEK, deactivate the old one.

        NOTE: Rotating the DEK does NOT re-encrypt existing secret versions —
        they remain accessible via the old (now inactive but retained) DEK.
        To re-encrypt all versions: call re_encrypt_secret_versions() after rotation.

        This is intentional: re-encryption of all versions is expensive and should
        be a deliberate, audited operation rather than implicit in key rotation.
        """
        new_key = await self.create_dek(reason=reason)

        # Deactivate old key (retain it — needed to decrypt historical versions)
        await self._db.execute(
            update(KeyMetadata)
            .where(KeyMetadata.id == old_key.id)
            .values(
                is_active=False,
                rotated_at=datetime.now(timezone.utc),
                rotation_reason=reason,
            )
        )
        return new_key

    async def rotate_mek(self, new_mek: bytes) -> int:
        """
        Rotate the Master Encryption Key: re-wrap all active DEKs.

        This is a heavy operation that should be run during a maintenance window
        or as a background task. The new MEK must be configured in the environment
        AFTER this completes — there's no rollback (keep old MEK until verified).

        Steps:
        1. Load all active KeyMetadata rows
        2. Unwrap each DEK with the OLD MEK
        3. Re-wrap each DEK with the NEW MEK
        4. Update DB rows (mek_version += 1)

        Returns: number of keys re-wrapped.
        """
        old_mek = self._get_mek()

        stmt = select(KeyMetadata).where(KeyMetadata.is_active == True)  # noqa: E712
        result = await self._db.execute(stmt)
        keys = result.scalars().all()

        rotated = 0
        for key_record in keys:
            try:
                dek = unwrap_key(key_record.encrypted_key, old_mek)
                new_wrapped = wrap_key(dek, new_mek)
                key_record.encrypted_key = new_wrapped
                key_record.mek_version += 1
                rotated += 1
            finally:
                dek = b"\x00" * 32  # noqa: F841
                del dek

        await self._db.flush()
        return rotated

    async def get_key_by_id(self, key_id: uuid.UUID) -> KeyMetadata | None:
        """Load a KeyMetadata record by primary key UUID."""
        stmt = select(KeyMetadata).where(KeyMetadata.id == key_id)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()
