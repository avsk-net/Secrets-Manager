# SecretManager — Threat Model

## Scope

This document covers security threats against the SecretManager API, its data stores,
and its runtime environment. It uses the STRIDE framework to classify threats and
documents the mitigations implemented.

---

## Assets

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Plaintext secret values | CRITICAL | Must never appear in DB, logs, error messages |
| Master Encryption Key (MEK) | CRITICAL | Compromise allows decrypting all DEKs |
| Data Encryption Keys (DEKs) | HIGH | Compromise allows decrypting one secret |
| JWT signing secret | HIGH | Allows forging arbitrary access tokens |
| Audit HMAC key | HIGH | Allows forging or tampering audit entries |
| User password hashes | HIGH | Argon2id hashed — resists offline cracking |
| Refresh tokens (DB) | HIGH | SHA-256 hashed — raw tokens not stored |
| Audit log entries | MEDIUM | Tamper-evident via HMAC chain |

---

## Threat Analysis (STRIDE)

### Spoofing

| Threat | Mitigation |
|--------|------------|
| Attacker forges JWT access token | HS256 signed with 64-byte secret; aud+iss validated on every request |
| Attacker replays stolen access token | Short TTL (15 min); JTI blocklist in Redis on logout |
| Attacker reuses refresh token after rotation | Token family revocation: presenting a revoked token revokes the entire family |
| Username enumeration via login timing | Argon2 hash always computed (dummy hash for nonexistent users) — equal timing |
| Attacker steals session via MITM | TLS enforced in production (HSTS, Strict-Transport-Security) |

### Tampering

| Threat | Mitigation |
|--------|------------|
| Attacker modifies encrypted secret in DB | AES-GCM auth tag detects any ciphertext modification (InvalidTag raised) |
| Attacker transplants ciphertext from secret A to B | AAD = `{secret_id}:{version}` — decryption fails if metadata doesn't match |
| Attacker modifies audit log entries | HMAC chain: every row's hash covers all prior hashes — breaks on any modification |
| Attacker inserts fake audit entries | HMAC chain: fake entries break subsequent hashes |
| Attacker modifies DB directly | Audit DB user has INSERT+SELECT only (no UPDATE/DELETE) in production |

### Repudiation

| Threat | Mitigation |
|--------|------------|
| User denies reading a secret | Every read emits an audit event with actor_id, timestamp, request_id, IP |
| Attacker disputes login events | HMAC chain protects audit entries from post-hoc modification |
| Deleted user's actions unattributable | actor_username denormalized in audit_logs — survives user deletion |

### Information Disclosure

| Threat | Mitigation |
|--------|------------|
| Secret values in logs | structlog sanitizes all log calls; `[REDACTED]` sentinel for sensitive fields |
| Secret values in error responses | Services return opaque errors (e.g., "Secret not found", not the value) |
| Secret values in DB | Only ciphertext stored — never plaintext |
| MEK in memory too long | DEK zeroed after use (best-effort — Python GC not guaranteed) |
| Timing oracle on token comparison | `hmac.compare_digest()` for all secret comparisons |
| Secrets in URL parameters | API design never puts secret values in URLs or query params |
| Server identification headers | `Server` and `X-Powered-By` headers removed |
| Debug endpoints in production | `/docs`, `/redoc`, `/openapi.json` disabled when `APP_ENV=production` |
| Cache poisoning revealing secrets | Cache keys are per-secret-id; secrets served from cache still go through auth |
| Verbose validation errors | 422 responses show field names but not secret values |

### Denial of Service

| Threat | Mitigation |
|--------|------------|
| Brute-force login | Rate limiting: 5 req/min per IP on auth endpoints |
| Account lockout (DoS against users) | Lockout is time-based (auto-unlocks) not permanent; attacker needs valid usernames |
| Secret enumeration | UUIDs for IDs (not sequential integers); rate limiting on read endpoints |
| Redis flooding | Global 1000 req/min per IP; Redis maxmemory policy configured |
| Large payload attacks | FastAPI request size limits; Pydantic field max_length validation |
| Slow POST attacks | uvicorn timeout configuration |

### Elevation of Privilege

| Threat | Mitigation |
|--------|------------|
| JWT scope tampering | Scopes derived server-side from role; custom scopes not accepted |
| Role escalation via API | `can_assign_role()` check: admins cannot assign super_admin |
| Developer accessing audit logs | Audit endpoints require `audit:read` scope (admin+ only) |
| Docker container escape | Non-root user (`smgr`); minimal base image; no volume mounts of sensitive host paths |
| Supply chain attacks | Dependencies pinned with minimum versions; `pip` from official PyPI |

---

## Cryptographic Decisions

### AES-256-GCM
- **Why:** AEAD primitive — confidentiality + integrity in one operation
- **Key size:** 256-bit (NIST post-2030 guidance)
- **Nonce:** 96-bit random (NIST SP 800-38D recommendation for GCM)
- **Tag:** 128-bit (default, maximum GCM tag size)
- **AAD:** `{secret_id}:{version}` — prevents ciphertext transplant attacks

### Argon2id
- **Why:** Memory-hard, GPU-resistant, NIST SP 800-63B recommended
- **Variant:** Argon2id (hybrid: side-channel resistant + GPU resistant)
- **Parameters:** t=3, m=64MiB, p=4 (OWASP minimum for interactive)
- **Transparent upgrade:** On login, stale hashes are upgraded automatically

### HMAC-SHA256 (Audit Chain)
- **Why:** Cryptographic binding between consecutive audit entries
- **Coverage:** `prev_hash || event_id || timestamp || actor_id || action || result`
- **Key:** Separate 64-byte AUDIT_HMAC_KEY (not reused for encryption)

### JWT (HS256)
- **Why:** Stateless, well-understood, widely supported
- **Key:** 64-byte (512-bit) secret — far above NIST 256-bit minimum for HS256
- **Claims validated:** `exp`, `nbf`, `aud`, `iss` on every request
- **Future:** Migrate to RS256 when resource servers need to verify tokens

---

## Deployment Security Requirements

### Production Checklist

- [ ] `APP_ENV=production` — disables Swagger, enables HSTS
- [ ] `APP_DEBUG=false`
- [ ] JWT_SECRET_KEY: 64+ hex chars from CSPRNG
- [ ] MASTER_ENCRYPTION_KEY: 32 bytes, URL-safe base64
- [ ] AUDIT_HMAC_KEY: 64 bytes, hex-encoded
- [ ] DB password: 32+ chars, random
- [ ] Redis password set
- [ ] TLS termination at load balancer with valid certificate
- [ ] DB audit_logs user has INSERT+SELECT only (no UPDATE/DELETE)
- [ ] Secrets not in version control (check `.gitignore`)
- [ ] BOOTSTRAP_ADMIN_PASSWORD removed after bootstrap
- [ ] Log aggregation without capturing response bodies
- [ ] Backup encryption: MEK backed up separately from DB backup

### Key Management Hardening

For production beyond a single node:
1. **KMS integration:** Replace `get_mek()` in `key_management.py` with AWS KMS / GCP KMS / HashiCorp Vault call
2. **Envelope encryption with KMS:** The MEK itself is a KMS data key; the KMS wraps it
3. **HSM:** For highest assurance, use an HSM for MEK storage
4. **MEK rotation schedule:** Rotate MEK annually; re-wrap all DEKs (automated in Celery beat)
5. **DEK rotation schedule:** Rotate DEKs every 90 days (automated in Celery beat)

---

## Known Limitations

| Limitation | Severity | Mitigation Path |
|------------|----------|-----------------|
| MEK in environment variable | MEDIUM | Migrate to KMS for production HA deployments |
| No mTLS between services | LOW | Add service mesh (Istio/Linkerd) for zero-trust networking |
| Single Redis instance | LOW | Add Redis Sentinel/Cluster for HA |
| Argon2 CPU blocking | LOW | Move to thread pool executor for high-concurrency load |
| Python GC doesn't guarantee key erasure | LOW | Known limitation; mitigated by short DEK lifetime in RAM |
| No field-level encryption in audit details | INFO | Audit details must not contain plaintext secrets (enforced by sanitize_details) |

---

## Incident Response

If MEK is compromised:
1. Rotate MEK immediately (`POST /api/v1/keys/rotate-mek`)
2. Re-wrap all DEKs with new MEK (done atomically in rotation endpoint)
3. Audit log all access since estimated compromise time
4. Consider re-encrypting all secret versions with new DEKs

If DB is exfiltrated:
- All secret values are AES-256-GCM encrypted → useless without DEKs
- DEKs are AES-256-GCM encrypted → useless without MEK
- Password hashes are Argon2id → resist offline cracking
- Refresh tokens are SHA-256 hashed → raw tokens not recoverable

If audit log tampering is detected:
1. Run `POST /api/v1/audit/verify-chain` to find first invalid entry
2. All entries after the first invalid one are suspect
3. Cross-reference with external immutable store (S3 object lock, transparency log)
