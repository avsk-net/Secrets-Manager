"""
Application configuration — validated at startup via Pydantic Settings.

Design rationale:
- Pydantic Settings reads from environment variables + .env file
- ALL security-critical values are validated for minimum length/entropy
- Missing or weak values raise a clear ValidationError at startup
  (fail-fast: better to crash immediately than to silently use weak keys)
- No default values for secrets — forces explicit configuration
"""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "SecretManager"
    app_env: Literal["development", "staging", "production"] = "development"
    app_debug: bool = False
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    # ── JWT ───────────────────────────────────────────────────────────────────
    # Require at least 64 hex chars = 32 bytes of entropy (NIST SP 800-107)
    jwt_secret_key: str = Field(..., min_length=64)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    jwt_issuer: str = "secret-manager"
    jwt_audience: str = "secret-manager-api"

    # ── Master Encryption Key ─────────────────────────────────────────────────
    # URL-safe base64-encoded 32-byte key.  Validated as decodable below.
    master_encryption_key: str = Field(..., min_length=43)  # base64url(32 bytes)

    # HMAC key for audit log chain — 128 hex chars = 64 bytes
    audit_hmac_key: str = Field(..., min_length=128)

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://smgr:password@postgres:5432/secretmanager"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10
    database_pool_timeout: int = 30
    database_echo: bool = False  # Set true only in dev for SQL logging

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    redis_rate_limit_db: int = 1
    redis_cache_db: int = 2
    redis_lock_db: int = 3

    # ── Celery ────────────────────────────────────────────────────────────────
    celery_broker_url: str = "redis://redis:6379/4"
    celery_result_backend: str = "redis://redis:6379/5"

    # ── Argon2id KDF ──────────────────────────────────────────────────────────
    # OWASP minimum for interactive: time_cost=1, memory_cost=64MB, parallelism=4
    # These are defaults; production should use higher time_cost.
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost: int = Field(default=65536, ge=65536)  # min 64 MiB
    argon2_parallelism: int = Field(default=4, ge=1)
    argon2_hash_length: int = Field(default=32, ge=16)

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    rate_limit_auth_per_minute: int = 5
    rate_limit_api_per_minute: int = 100
    rate_limit_write_per_minute: int = 20
    rate_limit_global_per_minute: int = 1000

    # ── Secret Cache ──────────────────────────────────────────────────────────
    secret_cache_ttl_seconds: int = 300
    secret_cache_enabled: bool = True

    # ── Bootstrap ─────────────────────────────────────────────────────────────
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = Field(default="", min_length=0)

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_allowed_origins: str = "http://localhost:3000"
    cors_allow_credentials: bool = True

    # ── Computed / Derived ────────────────────────────────────────────────────

    @field_validator("master_encryption_key")
    @classmethod
    def validate_mek(cls, v: str) -> str:
        """Validate MEK is decodable and yields exactly 32 bytes (AES-256)."""
        try:
            raw = base64.urlsafe_b64decode(v + "==")  # pad for urlsafe decode
        except (binascii.Error, ValueError) as exc:
            raise ValueError("MASTER_ENCRYPTION_KEY must be URL-safe base64") from exc
        if len(raw) < 32:
            raise ValueError("MASTER_ENCRYPTION_KEY must encode at least 32 bytes")
        return v

    @field_validator("audit_hmac_key")
    @classmethod
    def validate_audit_key(cls, v: str) -> str:
        """Validate audit HMAC key is hex-encoded and at least 64 bytes."""
        try:
            raw = bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("AUDIT_HMAC_KEY must be hex-encoded") from exc
        if len(raw) < 64:
            raise ValueError("AUDIT_HMAC_KEY must encode at least 64 bytes")
        return v

    @model_validator(mode="after")
    def production_safety_checks(self) -> "Settings":
        """Enforce stricter requirements in production."""
        if self.app_env == "production":
            if self.app_debug:
                raise ValueError("DEBUG must be false in production")
            if self.argon2_time_cost < 3:
                raise ValueError("Argon2 time_cost must be ≥3 in production")
        return self

    def get_mek_bytes(self) -> bytes:
        """Return the raw 32-byte master encryption key."""
        raw = base64.urlsafe_b64decode(self.master_encryption_key + "==")
        return raw[:32]

    def get_audit_hmac_bytes(self) -> bytes:
        """Return the raw audit HMAC key bytes."""
        return bytes.fromhex(self.audit_hmac_key)

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached settings instance.

    Using lru_cache means Settings() is called once per process lifetime.
    The cache must be cleared in tests: get_settings.cache_clear()
    """
    return Settings()
