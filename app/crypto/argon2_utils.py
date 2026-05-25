"""
Argon2id password hashing and key derivation.

Why Argon2id?
- Winner of the Password Hashing Competition (2015)
- Combines Argon2i (side-channel resistance) and Argon2d (GPU resistance)
- Memory-hard: each hash requires a configurable amount of RAM, making
  massively parallel attacks (GPU clusters) economically infeasible
- Time-hard: configurable number of passes over the memory buffer

Why NOT bcrypt or scrypt?
- bcrypt: max 72-byte password, no memory parameter, 1999-era design
- scrypt: harder to configure correctly, less widely analyzed
- PBKDF2: purely time-hard (no memory), weak against GPUs/ASICs
- Argon2id is NIST SP 800-63B recommended for modern systems

Parameter guidance (OWASP 2024):
  Interactive login (default): memory=64MiB, time=3, parallelism=4
  Passphrase-derived keys:     memory=256MiB, time=4, parallelism=8
  Adjust based on your hardware budget: aim for ~300ms per hash on
  your slowest API server, then tune up as hardware improves.

Thread safety:
- PasswordHasher is stateless and safe to use as a module-level singleton
- hash() and verify() are CPU-bound — in production with heavy load,
  consider offloading to a thread pool executor to avoid blocking the event loop
"""

from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw

from app.config import get_settings


def _build_hasher() -> PasswordHasher:
    """Build the Argon2id PasswordHasher from application settings."""
    cfg = get_settings()
    return PasswordHasher(
        time_cost=cfg.argon2_time_cost,
        memory_cost=cfg.argon2_memory_cost,
        parallelism=cfg.argon2_parallelism,
        hash_len=cfg.argon2_hash_length,
        # Argon2id = hybrid of Argon2i + Argon2d:
        #   Argon2i: data-independent memory access (side-channel resistant)
        #   Argon2d: data-dependent memory access (GPU resistant)
        #   Argon2id uses both in alternating passes — best of both worlds
        type=Type.ID,
    )


# Module-level singleton — instantiated once, reused for all hash/verify calls
_hasher: PasswordHasher | None = None


def get_hasher() -> PasswordHasher:
    global _hasher
    if _hasher is None:
        _hasher = _build_hasher()
    return _hasher


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.

    The hash string includes the algorithm, parameters, salt, and digest:
    $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

    This self-describing format means verification always uses the
    correct parameters, even after a parameter upgrade.

    Returns:
        PHC-format hash string safe to store in the DB.
    """
    return get_hasher().hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """
    Verify a password against its Argon2id hash.

    Returns True if correct, False if wrong password.
    Raises argon2.exceptions.InvalidHashError if the hash format is invalid.

    The verification is inherently constant-time due to Argon2's design
    (the comparison step uses hmac.compare_digest internally in argon2-cffi).
    """
    try:
        get_hasher().verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        # Malformed hash — treat as failure, not exception (prevents oracle)
        return False


def needs_rehash(hashed: str) -> bool:
    """
    Check if the stored hash needs to be recomputed with current parameters.

    Use this after successful login to transparently upgrade hashes when
    Argon2 parameters are increased (e.g., after a hardware upgrade).
    """
    return get_hasher().check_needs_rehash(hashed)


def derive_key(
    passphrase: str,
    salt: bytes | None = None,
    key_length: int = 32,
    time_cost: int = 4,
    memory_cost: int = 262144,  # 256 MiB — higher than login hashing
    parallelism: int = 8,
) -> tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a user-supplied passphrase using Argon2id.

    Use case: user-supplied encryption passphrases for additional secret
    protection layers (above and beyond envelope encryption).

    Higher parameters than login hashing because:
    1. This is done infrequently (key derivation, not per-request)
    2. The derived key protects sensitive cryptographic material
    3. Offline attack resistance is more important here

    Args:
        passphrase:  User-supplied passphrase.
        salt:        Optional 16-byte salt. Generated randomly if not provided.
        key_length:  Derived key length in bytes (default 32 = AES-256 key).
        time_cost:   Argon2 iteration count.
        memory_cost: Memory in KiB (default 256 MiB).
        parallelism: Thread count.

    Returns:
        (derived_key_bytes, salt_bytes)
        Both must be stored if you need to re-derive the same key later.
    """
    if salt is None:
        salt = os.urandom(16)

    # hash_secret_raw returns raw bytes (not PHC string format)
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_length,
        type=Type.ID,
    )
    return key, salt
