"""Initial schema — all tables for SecretManager v1.0.

Revision ID: 001_initial
Revises:
Create Date: 2025-01-01 00:00:00.000000

Design notes:
  - All primary keys are UUID (gen_random_uuid()) — prevents enumeration
  - Timestamps use TIMESTAMP WITH TIME ZONE — avoids DST bugs in forensics
  - audit_logs has NO foreign key to users.id (intentional):
      This prevents cascade deletes from destroying audit trail.
      actor_id is a nullable UUID column — not an FK.
  - Partial unique index on secrets(name, namespace) WHERE NOT is_deleted
      Allows re-creating a secret with the same name after deletion.
  - key_metadata rows are never deleted — RESTRICT on FK from secret_versions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="readonly"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_locked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role", "users", ["role"])
    op.create_index("ix_users_active", "users", ["is_active"])

    # ── refresh_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("family", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_user_family", "refresh_tokens", ["user_id", "family"])
    op.create_index("ix_refresh_tokens_expires", "refresh_tokens", ["expires_at"])

    # ── key_metadata ──────────────────────────────────────────────────────────
    op.create_table(
        "key_metadata",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("key_id", sa.String(100), nullable=False),
        sa.Column("algorithm", sa.String(50), nullable=False),
        sa.Column("encrypted_key", sa.LargeBinary(), nullable=False),
        sa.Column("mek_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotation_reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_id", name="uq_key_metadata_key_id"),
    )
    op.create_index("ix_key_metadata_key_id", "key_metadata", ["key_id"])
    op.create_index("ix_key_metadata_active", "key_metadata", ["is_active"])

    # ── secrets ───────────────────────────────────────────────────────────────
    op.create_table(
        "secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("namespace", sa.String(255), nullable=False, server_default="default"),
        sa.Column("secret_type", sa.String(20), nullable=False, server_default="kv"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "namespace", name="uq_secret_name_namespace"),
    )
    op.create_index("ix_secrets_namespace", "secrets", ["namespace"])
    op.create_index("ix_secrets_deleted", "secrets", ["is_deleted"])
    op.create_index("ix_secrets_created_by", "secrets", ["created_by_id"])
    # Partial index: efficient lookup for active secrets only
    op.execute(
        "CREATE INDEX ix_secrets_active_name_ns ON secrets (name, namespace) "
        "WHERE is_deleted = false"
    )

    # ── secret_versions ───────────────────────────────────────────────────────
    op.create_table(
        "secret_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("secret_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default="false"),
        sa.ForeignKeyConstraint(["secret_id"], ["secrets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["key_id"], ["key_metadata.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("secret_id", "version", name="uq_secret_version"),
    )
    op.create_index("ix_secret_versions_secret_id", "secret_versions", ["secret_id"])
    op.create_index("ix_secret_versions_current", "secret_versions", ["secret_id", "is_current"])
    op.create_index("ix_secret_versions_key", "secret_versions", ["key_id"])

    # ── audit_logs ────────────────────────────────────────────────────────────
    # actor_id is NOT a FK to users — deliberate (see module docstring)
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_username", sa.String(100), nullable=True),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", name="uq_audit_logs_event_id"),
    )
    op.create_index("ix_audit_logs_event_id", "audit_logs", ["event_id"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_actor_ts", "audit_logs", ["actor_id", "timestamp"])
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_logs_result", "audit_logs", ["result"])

    # Trigger to update secrets.updated_at automatically
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN NEW.updated_at = now(); RETURN NEW; END;
        $$ language 'plpgsql'
    """)
    for table in ("users", "secrets", "key_metadata"):
        op.execute(f"""
            CREATE TRIGGER {table}_updated_at
            BEFORE UPDATE ON {table}
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
        """)


def downgrade() -> None:
    for table in ("users", "secrets", "key_metadata"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_updated_at ON {table}")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")

    op.drop_table("audit_logs")
    op.drop_table("secret_versions")
    op.drop_table("secrets")
    op.drop_table("key_metadata")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
