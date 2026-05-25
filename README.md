# SecretManager

A production-grade **Distributed Secrets Manager** inspired by HashiCorp Vault.
Built with Python 3.12, FastAPI, PostgreSQL, and Redis.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Clients                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
                ┌───────────▼────────────┐
                │   FastAPI Application  │  (4 uvicorn workers)
                │  ┌──────────────────┐  │
                │  │ Security Headers │  │
                │  │  Rate Limiting   │  │
                │  │  Request ID      │  │
                │  │  CORS            │  │
                │  └──────────────────┘  │
                │  ┌──────────────────┐  │
                │  │  JWT Auth/RBAC   │  │
                │  └──────────────────┘  │
                │  ┌──────────────────┐  │
                │  │   API Routers    │  │
                │  │ auth/secrets/    │  │
                │  │ users/audit      │  │
                │  └──────────────────┘  │
                │  ┌──────────────────┐  │
                │  │    Services      │  │
                │  └──────────────────┘  │
                └──────┬────────┬────────┘
                       │        │
          ┌────────────▼──┐  ┌──▼──────────────┐
          │  PostgreSQL   │  │     Redis        │
          │               │  │                  │
          │ users         │  │ token_revocation │
          │ refresh_tokens│  │ rate_limiting    │
          │ key_metadata  │  │ secret_cache     │
          │ secrets       │  │ dist_locks       │
          │ secret_versions│ │ celery_broker    │
          │ audit_logs    │  └──────────────────┘
          └───────────────┘
                ┌─────────────────────┐
                │   Celery Worker     │
                │ cleanup_tokens      │
                │ rotate_deks         │
                │ invalidate_cache    │
                └─────────────────────┘
```

## Envelope Encryption (3-Tier Key Hierarchy)

```
Root Key / MEK  (env var or KMS)
    │
    └──wraps──► DEK (per secret, stored encrypted in key_metadata)
                    │
                    └──encrypts──► Secret Version Payload
                                   (AES-256-GCM, unique nonce per version)
                                   AAD = "{secret_id}:{version}"
```

**Why envelope encryption?**
- Rotating the MEK only requires re-wrapping DEKs, not re-encrypting all data
- Compromising one DEK only exposes one secret
- The MEK never directly touches user data

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.12+ (for local development)

### 1. Generate secrets

```bash
make generate-keys
```

Copy the output to `.env` (created from `.env.example`):

```bash
cp .env.example .env
# Edit .env with the generated keys
```

### 2. Start services

```bash
make up
```

### 3. Run migrations

```bash
make migrate
```

### 4. Bootstrap admin

```bash
# Add to .env:
# BOOTSTRAP_ADMIN_USERNAME=admin
# BOOTSTRAP_ADMIN_EMAIL=admin@company.com
# BOOTSTRAP_ADMIN_PASSWORD=YourStrongPassword123!

make bootstrap
# Then remove BOOTSTRAP_ADMIN_PASSWORD from .env
```

### 5. Verify

```bash
make health
# → {"status": "ok", "version": "1.0.0"}
```

Browse API docs: http://localhost:8000/docs

---

## API Reference

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourPassword"}'

# Response
{
  "access_token": "eyJhbGci...",
  "refresh_token": "d2h5...",
  "token_type": "bearer",
  "expires_in": 900,
  "scope": ["secrets:read", "secrets:write", ...]
}

# Refresh
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "d2h5..."}'

# Logout
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "d2h5..."}'
```

### Secrets

```bash
export TOKEN="eyJhbGci..."

# Create a KV secret
curl -X POST http://localhost:8000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod/db/password",
    "namespace": "production",
    "secret_type": "kv",
    "value": "supersecret123"
  }'

# Create a JSON secret
curl -X POST http://localhost:8000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod/api/config",
    "namespace": "production",
    "secret_type": "json",
    "value": {"host": "db.internal", "port": 5432}
  }'

# Read a secret (decrypted)
curl http://localhost:8000/api/v1/secrets/{id} \
  -H "Authorization: Bearer $TOKEN"

# Update (creates new version)
curl -X PUT http://localhost:8000/api/v1/secrets/{id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "new_value"}'

# List versions
curl http://localhost:8000/api/v1/secrets/{id}/versions \
  -H "Authorization: Bearer $TOKEN"

# Read specific version
curl http://localhost:8000/api/v1/secrets/{id}/versions/2 \
  -H "Authorization: Bearer $TOKEN"

# Rollback to version 1
curl -X POST http://localhost:8000/api/v1/secrets/{id}/rollback \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"version": 1}'

# Delete (soft delete)
curl -X DELETE http://localhost:8000/api/v1/secrets/{id} \
  -H "Authorization: Bearer $TOKEN"

# List all secrets (no values)
curl "http://localhost:8000/api/v1/secrets?namespace=production&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

### Audit Log

```bash
# Query audit events
curl "http://localhost:8000/api/v1/audit/logs?event_type=secret.read&page=1" \
  -H "Authorization: Bearer $TOKEN"

# Filter by actor
curl "http://localhost:8000/api/v1/audit/logs?actor_id={user_uuid}" \
  -H "Authorization: Bearer $TOKEN"

# Verify chain integrity
curl -X POST http://localhost:8000/api/v1/audit/verify-chain \
  -H "Authorization: Bearer $TOKEN"
# → {"valid": true, "checked_entries": 1523, "message": "Chain valid across 1523 entries"}
```

---

## RBAC Permission Matrix

| Endpoint | readonly | developer | admin | super_admin |
|----------|----------|-----------|-------|-------------|
| GET /secrets | ✅ | ✅ | ✅ | ✅ |
| POST /secrets | ❌ | ✅ | ✅ | ✅ |
| PUT /secrets/{id} | ❌ | ✅ | ✅ | ✅ |
| DELETE /secrets/{id} | ❌ | ❌ | ✅ | ✅ |
| POST /secrets/{id}/rollback | ❌ | ✅ | ✅ | ✅ |
| GET /users | ❌ | ❌ | ✅ | ✅ |
| POST /users | ❌ | ❌ | ✅* | ✅ |
| GET /audit/logs | ❌ | ❌ | ✅ | ✅ |
| POST /audit/verify-chain | ❌ | ❌ | ✅ | ✅ |

*admin can create users up to admin role (no privilege escalation to super_admin)

---

## Security Features

### Encryption at Rest
- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key size:** 256-bit Data Encryption Keys
- **Nonce:** 96-bit random per version (NIST SP 800-38D)
- **AAD:** `{secret_id}:{version}` prevents ciphertext transplant attacks

### Key Derivation
- **Algorithm:** Argon2id (OWASP recommended, 2024)
- **Parameters:** t=3, m=64MiB, p=4 (configurable)
- **Transparent rehashing:** Upgrades hashes on next login when parameters increase

### Authentication
- **Access tokens:** JWT HS256, 15-minute TTL, aud+iss validated
- **Refresh tokens:** 32-byte opaque tokens, SHA-256 hashed in DB, 7-day TTL
- **Token rotation:** Every refresh issues a new pair, old token revoked
- **Reuse detection:** Presenting a revoked token revokes the entire token family

### Audit Log Integrity
- **Append-only:** No UPDATE or DELETE methods in AuditRepository
- **HMAC chain:** Each entry covers `prev_hash || event_id || timestamp || actor || result`
- **Tamper detection:** `POST /audit/verify-chain` detects any modification
- **Forensic metadata:** IP address, user agent, request ID on every event

### Rate Limiting
- Login: 5 requests/minute/IP
- Write ops: 20 requests/minute/user
- Read ops: 100 requests/minute/user
- Global: 1000 requests/minute/IP

---

## Project Structure

```
app/
├── main.py              # FastAPI app factory + lifespan
├── config.py            # Pydantic Settings (validated at startup)
├── domain/
│   ├── enums.py         # UserRole, Scope, SecretType, AuditEventType
│   ├── models/          # SQLAlchemy 2.0 ORM models
│   └── schemas/         # Pydantic v2 request/response schemas
├── crypto/
│   ├── engine.py        # AES-256-GCM encrypt/decrypt
│   ├── key_management.py# Envelope encryption lifecycle
│   └── argon2_utils.py  # Argon2id hash/verify/derive
├── auth/
│   ├── jwt_handler.py   # JWT creation/validation/revocation
│   ├── rbac.py          # Scope/permission checking
│   └── dependencies.py  # FastAPI Depends() helpers
├── repositories/        # Async SQLAlchemy data access layer
├── services/            # Business logic + orchestration
├── api/
│   ├── v1/              # Route handlers (auth, secrets, users, audit)
│   └── middleware/      # Rate limiting, security headers, request ID
└── audit/
    └── logger.py        # Append-only audit event emitter
```

---

## Testing

```bash
# All tests
make test

# Unit tests only (no DB/Redis needed)
make test-unit

# Integration tests
make test-integration

# Security/permission tests
make test-security
```

Test coverage target: **80%+**

Key test areas:
- `tests/unit/test_crypto.py` — Encryption, nonce uniqueness, AAD binding, timing
- `tests/unit/test_auth.py` — JWT validation, scope checking, Argon2
- `tests/integration/test_secrets.py` — Full CRUD + versioning via HTTP
- `tests/security/test_permissions.py` — RBAC matrix for all roles × endpoints

---

## Configuration Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET_KEY` | ✅ | 64+ hex chars for JWT signing |
| `MASTER_ENCRYPTION_KEY` | ✅ | Base64url 32-byte MEK |
| `AUDIT_HMAC_KEY` | ✅ | 128+ hex chars for audit chain HMAC |
| `DATABASE_URL` | ✅ | PostgreSQL async URL |
| `REDIS_URL` | ✅ | Redis connection URL |
| `ARGON2_TIME_COST` | default: 3 | Argon2 iteration count |
| `ARGON2_MEMORY_COST` | default: 65536 | Argon2 memory (KiB) |
| `APP_ENV` | default: development | `development` / `staging` / `production` |

See `.env.example` for full reference.

---

## Phased Implementation Roadmap

### Phase 1 — MVP ✅ (This release)
- Secure secret storage (AES-256-GCM envelope encryption)
- Argon2id KDF, JWT + refresh tokens, RBAC
- Secret versioning + rollback
- Append-only audit log with HMAC chain
- Rate limiting, security headers
- Docker Compose, migrations, tests

### Phase 2 — Production Hardening
- KMS integration (AWS KMS / GCP KMS) replacing env-var MEK
- RS256 JWT for multi-service token verification
- DB connection with INSERT-only audit log user
- Distributed Redlock for DEK creation (vs simple SETNX)
- mTLS between API and DB/Redis
- Prometheus metrics endpoint
- Structured JSON logging to ELK stack

### Phase 3 — HA / Distributed Deployment
- Active-active API nodes (already stateless)
- Redis Cluster for distributed cache/locks
- PostgreSQL read replicas for audit log queries
- Celery workers with task idempotency keys
- Database partitioning for audit_logs (range by month)
- MEK rotation with zero-downtime (two-MEK overlap window)

### Phase 4 — Enterprise Extensions
- **Secret leasing:** TTL-based automatic expiry + renewal API
- **Dynamic credentials:** Celery generates ephemeral DB users, rotates on lease expiry
- **Policy engine:** OPA-style rules (`namespace:prod → requires admin`)
- **Service-to-service auth:** Client credentials flow + mTLS
- **WebSocket audit stream:** Real-time event feed for SIEM integration
- **Admin dashboard API:** Usage metrics, key rotation status, health
- **Key rotation scheduler:** Admin-configurable rotation intervals per namespace
- **Secret sharing:** Shamir's Secret Sharing for M-of-N key reconstruction

---

## License

MIT — See LICENSE file.
