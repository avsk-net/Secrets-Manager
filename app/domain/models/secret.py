"""
Secret, SecretVersion, and KeyMetadata models.

Envelope encryption layout:
  KeyMetadata  ──(wrapped DEK)──▶  used by  ──▶  SecretVersion.encrypted_value
                                                   + SecretVersion.nonce

Each Secret has exactly ONE active SecretVersion (is_current=True) at a time.
Every update creates a NEW SecretVersion row — no in-place mutation.
This gives us:
  - Immutable version history (forensic value)
  - Safe rollback (flip is_current)
  - No plaintext ever stored (encrypted_value is always ciphertext)

Checksum (HMAC-SHA256 of plaintext) is stored alongside ciphertext to verify
decryption correctness without re-encrypting — this catches key/nonce corruption
without exposing the plaintext.

Soft delete: is_deleted=True + deleted_at timestamp. Deleted secrets can be
restored by super_admin within the retention window.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.domain.enums import SecretType


class KeyMetadata(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Tracks Data Encryption Keys (DEKs) in wrapped (encrypted) form.

    The `encrypted_key` column stores: AES-GCM( plaintext_DEK, MEK )
    It is NEVER stored in plaintext — the MEK is required to unwrap it.

    key_version allows tracking MEK rotations: when the MEK rotates,
    all DEKs are re-wrapped under the new MEK and key_version incremented.
    """

    __tablename__ = "key_metadata"

    # Human-readable key identifier (e.g., "key_<ulid>")
    key_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    algorithm: Mapped[str] = mapped_column(
        String(50), nullable=False, default="AES-256-GCM"
    )

    # AES-GCM( raw_32_byte_DEK, MEK ) — includes nonce prepended
    encrypted_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # MEK version used to wrap this DEK (incremented on MEK rotation)
    mek_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Back-ref to all versions using this key
    secret_versions: Mapped[list["SecretVersion"]] = relationship(
        "SecretVersion",
        back_populates="key",
        lazy="noload",
    )

    __table_args__ = (Index("ix_key_metadata_active", "is_active"),)

    def __repr__(self) -> str:
        return f"<KeyMetadata key_id={self.key_id!r} active={self.is_active}>"


class Secret(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Logical secret entity — the durable identifier for a named credential.

    The actual sensitive value lives in SecretVersion rows, never here.
    current_version tracks the latest version number for fast lookup.
    """

    __tablename__ = "secrets"

    # Namespaced name: e.g., "prod/db/password", "staging/api/key"
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    namespace: Mapped[str] = mapped_column(String(255), nullable=False, default="default")

    secret_type: Mapped[SecretType] = mapped_column(
        String(20), nullable=False, default=SecretType.KV
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Who created this secret (preserved even if user is later deleted — UUID ref)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # Latest active version number — avoids a MAX(version) query on reads
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    created_by: Mapped["User"] = relationship(  # noqa: F821
        "User",
        foreign_keys=[created_by_id],
        back_populates="created_secrets",
        lazy="noload",
    )
    versions: Mapped[list["SecretVersion"]] = relationship(
        "SecretVersion",
        back_populates="secret",
        lazy="noload",
        order_by="SecretVersion.version.desc()",
    )

    __table_args__ = (
        # Uniqueness enforced via partial index — same name/ns can be reused after delete
        UniqueConstraint("name", "namespace", name="uq_secret_name_namespace"),
        Index("ix_secrets_namespace", "namespace"),
        Index("ix_secrets_deleted", "is_deleted"),
        Index("ix_secrets_created_by", "created_by_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<Secret id={self.id} name={self.name!r} "
            f"ns={self.namespace!r} v={self.current_version}>"
        )


class SecretVersion(Base, UUIDPrimaryKeyMixin):
    """
    Immutable version of a secret's encrypted payload.

    Immutability contract:
    - Rows are INSERT-only after creation (no UPDATE)
    - is_current is the single exception: flipped via the secret_service
      when a new version is created or rollback requested
    - version numbers are monotonically increasing per secret

    Encryption layout (all stored as bytes):
        nonce        :  12 bytes  — unique AES-GCM nonce (96-bit)
        encrypted_value: ciphertext + 16-byte GCM auth tag
        key_id → KeyMetadata → encrypted DEK → unwrapped with MEK → decrypt

    AAD (Additional Authenticated Data) binds ciphertext to this exact
    (secret_id, version) pair — prevents copying a valid ciphertext to a
    different secret or version number.
    """

    __tablename__ = "secret_versions"

    secret_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("secrets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    version: Mapped[int] = mapped_column(Integer, nullable=False)

    # Ciphertext bytes (includes GCM auth tag — NOT detached)
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # 12-byte (96-bit) random nonce — unique per version
    # 96-bit nonces with GCM: collision probability < 2^-32 at 4 billion messages
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)

    # FK to the KeyMetadata row whose DEK encrypted this version
    key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("key_metadata.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # HMAC-SHA256(plaintext) — used to verify decryption without logging plaintext
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)

    # Optional metadata tags: {"env": "prod", "owner": "platform-team"}
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    # Who created (wrote) this version
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    secret: Mapped["Secret"] = relationship(
        "Secret",
        back_populates="versions",
        lazy="noload",
    )
    key: Mapped["KeyMetadata"] = relationship(
        "KeyMetadata",
        back_populates="secret_versions",
        lazy="noload",
    )
    created_by: Mapped["User"] = relationship(  # noqa: F821
        "User",
        foreign_keys=[created_by_id],
        lazy="noload",
    )

    __table_args__ = (
        UniqueConstraint("secret_id", "version", name="uq_secret_version"),
        Index("ix_secret_versions_current", "secret_id", "is_current"),
        Index("ix_secret_versions_key", "key_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecretVersion secret_id={self.secret_id} "
            f"v={self.version} current={self.is_current}>"
        )
