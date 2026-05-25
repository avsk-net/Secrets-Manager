# SecretManager — Architecture Documentation

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENT TIER                                │
│           CLI / SDK / Dashboard / Service-to-Service                   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTPS (TLS 1.3)
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│                            API TIER (Stateless)                         │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │               FastAPI Application (uvicorn)                     │   │
│  │                                                                 │   │
│  │  Middleware Stack (outermost → innermost):                      │   │
│  │    SecurityHeadersMiddleware → RateLimitMiddleware              │   │
│  │    → RequestIDMiddleware → CORSMiddleware                       │   │
│  │                                                                 │   │
│  │  Auth Layer:                                                    │   │
│  │    JWT verification → JTI revocation check (Redis)             │   │
│  │    → User active check (DB) → Scope check (RBAC)               │   │
│  │                                                                 │   │
│  │  API Routers (v1):                                              │   │
│  │    /auth    /secrets    /users    /audit                       │   │
│  │                                                                 │   │
│  │  Service Layer:                                                 │   │
│  │    AuthService → SecretService → UserService → AuditLogger     │   │
│  │                                                                 │   │
│  │  Crypto Layer:                                                  │   │
│  │    CryptoEngine (AES-256-GCM) ← KeyManagementService          │   │
│  │    Argon2Utils                                                  │   │
│  │                                                                 │   │
│  │  Repository Layer:                                              │   │
│  │    UserRepo  SecretRepo  AuditRepo  TokenRepo  KeyRepo         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────┬────────────────────────────┬──────────────────────────────┘
              │ asyncpg (async TCP)         │ redis-py (async)
              │                             │
┌─────────────▼──────────┐  ┌──────────────▼──────────────────────────────┐
│      PostgreSQL 16      │  │                 Redis 7                     │
│                        │  │                                              │
│  Tables:               │  │  DB 0 - General (session state)             │
│  ├── users             │  │  DB 1 - Rate limit counters                 │
│  ├── refresh_tokens    │  │  DB 2 - Secret cache (TTL-based)            │
│  ├── key_metadata      │  │  DB 3 - Distributed locks                   │
│  ├── secrets           │  │  DB 4 - Celery broker                       │
│  ├── secret_versions   │  │  DB 5 - Celery results                      │
│  └── audit_logs        │  │  revoked_jti:{jti} (access token revocation)│
│                        │  │  rl:{scope}:{ip} (rate limit counters)      │
│  Indexes:              │  │  lock:dek:create:{id} (DEK creation lock)   │
│  ├── Partial idx on    │  │  secret:cache:{id} (decrypted secret cache) │
│  │   secrets(active)   │  └──────────────────────────────────────────────┘
│  ├── Composite idx on  │
│  │   audit(actor,ts)   │  ┌──────────────────────────────────────────────┐
│  └── HMAC chain idx    │  │           Celery Worker + Beat               │
└────────────────────────┘  │                                              │
                            │  Tasks:                                      │
                            │  ├── cleanup_expired_tokens (*/15min)       │
                            │  ├── rotate_old_deks (daily 02:00 UTC)      │
                            │  ├── worker_health_check (*/5min)           │
                            │  └── invalidate_secret_cache (on-demand)    │
                            └──────────────────────────────────────────────┘
```

## Data Flow: Secret Write

```
Client                  API                  Crypto Layer            DB
  │                      │                        │                   │
  │──POST /secrets──────►│                        │                   │
  │                      │──verify JWT────────────►── (Redis check)   │
  │                      │◄─token_payload─────────│                   │
  │                      │──check scope───────────►                   │
  │                      │◄─allowed───────────────│                   │
  │                      │                        │                   │
  │                      │──get_or_create_dek──────────────────────►  │
  │                      │◄─key_metadata───────────────────────────── │
  │                      │                        │                   │
  │                      │──get_dek(key_metadata)─►                   │
  │                      │  (unwrap DEK from MEK)  │                   │
  │                      │◄─raw_dek (32 bytes)────│                   │
  │                      │                        │                   │
  │                      │──build_aad──────────────►                  │
  │                      │  ("{secret_id}:{ver}")  │                   │
  │                      │                        │                   │
  │                      │──encrypt(plain,dek,aad)►                   │
  │                      │◄─EncryptedBlob──────────│                   │
  │                      │  (ciphertext, nonce)    │                   │
  │                      │                        │                   │
  │                      │──compute_checksum───────►                  │
  │                      │◄─hmac_hex───────────────│                   │
  │                      │                        │                   │
  │                      │──zero_fill(dek)─────────►                  │
  │                      │                        │                   │
  │                      │──INSERT secret_version──────────────────►  │
  │                      │  (encrypted_value,      │                  │
  │                      │   nonce, key_id,         │                  │
  │                      │   checksum)              │                  │
  │                      │◄─committed──────────────────────────────── │
  │                      │                        │                   │
  │                      │──emit_audit_event────────────────────────► │
  │                      │  (SECRET_CREATE)        │                  │
  │                      │                        │                   │
  │◄─201 Created─────────│                        │                   │
  │  (no value in resp)  │                        │                   │
```

## Data Flow: Secret Read (with Cache)

```
Client              API            Redis           DB
  │                  │               │               │
  │──GET /secrets/id►│               │               │
  │                  │──auth_check──►│               │
  │                  │◄─ok───────────│               │
  │                  │               │               │
  │                  │──cache_get────►               │
  │                  │◄─hit/miss──────               │
  │                  │               │               │
  │    (cache miss)  │────────────────────load_sv──► │
  │                  │◄──────────────────sv+key───── │
  │                  │                               │
  │                  │──unwrap_dek(key_metadata)     │
  │                  │  MEK → DEK                    │
  │                  │──decrypt(cipher,dek,nonce,aad)│
  │                  │──verify_checksum              │
  │                  │──zero_fill(dek)               │
  │                  │                               │
  │                  │──cache_set (TTL 5min)──►      │
  │                  │──emit_audit(SECRET_READ)─────►│
  │                  │                               │
  │◄─200 + value─────│                               │
```

## Key Management State Machine

```
DEK Lifecycle:
  ┌──────────┐  create_dek()  ┌────────┐  rotate_dek()  ┌──────────┐
  │ (none)   │───────────────►│ ACTIVE │───────────────►│ INACTIVE │
  └──────────┘                └────────┘                └──────────┘
                                  │                          │
                             used to encrypt           retained for
                             new versions              decrypting old
                                                       versions

MEK Rotation (rotate_mek(new_mek)):
  For each active KeyMetadata:
    old_dek = AES-GCM-decrypt(encrypted_key, old_mek)
    new_wrapped = AES-GCM-encrypt(old_dek, new_mek)
    UPDATE key_metadata SET encrypted_key=new_wrapped, mek_version+=1
  (No re-encryption of secret_versions — old DEKs still work)
```

## Audit Log Chain

```
Entry 1 (first entry):
  prev_hash  = NULL
  chain_hash = HMAC-SHA256(key,
                 "" || event_id_1 || ts_1 || actor_1 || action_1 || result_1)

Entry 2:
  prev_hash  = chain_hash of entry 1
  chain_hash = HMAC-SHA256(key,
                 chain_hash_1 || event_id_2 || ts_2 || actor_2 || action_2 || result_2)

Entry N:
  prev_hash  = chain_hash of entry N-1
  chain_hash = HMAC-SHA256(key, chain_hash_{N-1} || fields_N)

Tamper scenario:
  Modify entry 3's action field:
    entry_3.chain_hash no longer matches HMAC(prev_hash_3 || modified_fields)
    entry_4.chain_hash was computed from entry_3's original chain_hash
    → entry_4 through entry_N all have broken chains
    → /audit/verify-chain reports first_invalid_event_id = entry_3.event_id
```

## Authentication Flow

```
Login:
  POST /auth/login
  → Argon2id.verify(stored_hash, password)     [always runs — no timing leak]
  → failed_login_attempts++ (if wrong)          [account lock after 5 failures]
  → create_access_token(user_id, role)          [15-min JWT]
  → create_refresh_token()                      [opaque, 7-day]
  → store hash(refresh_token) + family in DB
  → return {access_token, refresh_token}

Refresh:
  POST /auth/refresh  {refresh_token: "..."}
  → hash(refresh_token)
  → lookup in DB
  if REVOKED:
    → revoke_family(family_id)                 [theft detected]
    → 401
  if VALID:
    → revoke old token
    → create new pair (same family)
    → return {new_access_token, new_refresh_token}

Logout:
  POST /auth/logout  {refresh_token: "..."}
  + Authorization: Bearer {access_token}
  → revoke refresh token in DB
  → add access JTI to Redis blocklist (TTL = remaining token lifetime)

API Request:
  → verify JWT signature + exp + aud + iss
  → check JTI in Redis blocklist
  → load user from DB (verify is_active, not is_locked)
  → check required scope in token.scopes
```

## Distributed Consistency Model

```
Write consistency: STRONG
  All writes go to PostgreSQL (single primary)
  Transactions ensure atomicity of:
    - secret + audit_event (both committed or both rolled back)
    - version creation + current_version update

Read consistency: EVENTUAL (cache layer)
  Secret reads may return cached data (up to 5 min stale)
  Cache is invalidated immediately after writes
  For strict consistency: disable SECRET_CACHE_ENABLED

Distributed locking (DEK creation):
  Redis SETNX for DEK creation race prevention
  Lock TTL: 5 seconds (prevents stale lock if holder crashes)
  Production: use Redlock algorithm for HA Redis setups

Token revocation:
  JTI blocklist: Redis (fast, TTL-based cleanup)
  Refresh tokens: PostgreSQL (durable)
  Cross-node: All nodes share same Redis → immediate propagation
```

## Scalability Considerations

```
Horizontal scaling:
  API nodes: stateless → scale freely behind load balancer
  Workers: Celery tasks are idempotent → scale workers independently
  DB reads: add read replicas for audit log queries
  DB writes: limited by PostgreSQL single-primary write throughput
    → partition secret_versions by secret_id for write-heavy workloads
    → partition audit_logs by month for query-heavy compliance workloads

Rate limiting:
  Redis-based → shared across all API nodes
  No per-node memory → consistent limits under horizontal scaling

Cache:
  Redis shared cache → all nodes see same cached values
  Cache invalidation: immediate after write (delete, not TTL-wait)

Bottlenecks (in order):
  1. Argon2id login: ~300ms per login on commodity hardware
     → rate limiting protects this; horizontal scaling helps
  2. Key unwrapping on every secret read
     → DEK can be cached in Redis (encrypted, not plaintext) for hot secrets
  3. Audit log inserts: sequential writes for chain building
     → partition audit_logs; use ULID for lexicographic ordering
```
