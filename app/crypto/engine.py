"""
AES-256-GCM symmetric encryption engine.

Why AES-256-GCM?
- Industry standard authenticated encryption (AEAD)
- Provides BOTH confidentiality AND integrity in one operation
- 256-bit key size exceeds NIST recommendation for long-term security
- Hardware acceleration on modern CPUs (AES-NI)
- GCM mode is parallelizable (unlike CBC) and stream-friendly

Why NOT AES-CBC?
- Requires separate MAC (HMAC) for integrity — easy to get wrong
- Padding oracle attacks (POODLE, BEAST) if implemented incorrectly
- AES-GCM eliminates these concerns with a single primitive

Nonce / IV design:
- 96-bit (12-byte) random nonce recommended by NIST SP 800-38D for GCM
- Each nonce MUST be unique per (key, message) pair
- With random nonces: birthday bound ≈ 2^32 messages per key before
  collision probability exceeds 2^-32 — we enforce key rotation
  well before this limit via the key rotation scheduler

AAD (Additional Authenticated Data):
- AAD is authenticated but NOT encrypted
- We use AAD = secret_id || ":" || version_str
- This cryptographically binds ciphertext to its metadata:
  an attacker cannot take ciphertext from secret A and transplant
  it to secret B (the AAD check would fail on decrypt)
- This prevents ciphertext-transplant attacks even if the DB is compromised

Tag size:
- GCM authentication tag is 128 bits (16 bytes)
- Appended to ciphertext by the cryptography library automatically
- Any bit-flip in ciphertext or tag causes decrypt to raise InvalidTag
"""

from __future__ import annotations

import hmac
import os
import secrets
from hashlib import sha256
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# GCM nonce size: 96 bits as recommended by NIST SP 800-38D section 8.2
NONCE_SIZE = 12

# AES-256 key size: 32 bytes = 256 bits
KEY_SIZE = 32

# GCM auth tag size: 128 bits (16 bytes) — included in ciphertext by cryptography lib
TAG_SIZE = 16


class EncryptedBlob(NamedTuple):
    """
    Result of an encryption operation.

    ciphertext includes the GCM authentication tag (last 16 bytes).
    nonce must be stored alongside ciphertext for decryption.
    """

    ciphertext: bytes  # encrypted_data || tag
    nonce: bytes       # 12-byte GCM nonce


def generate_nonce() -> bytes:
    """
    Generate a cryptographically random 96-bit GCM nonce.

    Uses os.urandom() which reads from /dev/urandom on Linux —
    the OS CSPRNG, seeded by hardware entropy sources.
    NEVER use random.randbytes() or similar non-cryptographic PRNGs.
    """
    return os.urandom(NONCE_SIZE)


def generate_dek() -> bytes:
    """
    Generate a random 256-bit Data Encryption Key.

    Returns raw bytes (not base64) — the caller is responsible
    for wrapping/storing securely.  Never log or print this value.
    """
    return secrets.token_bytes(KEY_SIZE)


def encrypt(
    plaintext: bytes,
    key: bytes,
    aad: bytes | None = None,
) -> EncryptedBlob:
    """
    Encrypt plaintext using AES-256-GCM with a fresh random nonce.

    Args:
        plaintext: The data to encrypt.
        key:       32-byte AES-256 key (DEK).
        aad:       Additional Authenticated Data — authenticated but not encrypted.
                   Use: aad = f"{secret_id}:{version}".encode()

    Returns:
        EncryptedBlob(ciphertext, nonce)
        The ciphertext includes the 16-byte GCM auth tag.

    Raises:
        ValueError: if key length != 32 bytes
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return EncryptedBlob(ciphertext=ciphertext, nonce=nonce)


def decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes | None = None,
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    The GCM authentication tag is verified as part of decryption.
    If the tag is invalid (data tampered, wrong key, wrong nonce,
    or wrong AAD), InvalidTag is raised before any plaintext is returned.

    Args:
        ciphertext: Encrypted bytes including the 16-byte auth tag.
        key:        32-byte AES-256 key.
        nonce:      12-byte nonce used during encryption.
        aad:        Must match the AAD used during encryption exactly.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        InvalidTag:  If authentication fails (tampered data, wrong key/nonce/aad)
        ValueError:  If key or nonce length is incorrect
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    # This raises InvalidTag if authentication fails — do NOT catch this exception
    # in most contexts; let it propagate as a security signal
    return aesgcm.decrypt(nonce, ciphertext, aad)


def wrap_key(dek: bytes, mek: bytes) -> bytes:
    """
    Encrypt (wrap) a Data Encryption Key using the Master Encryption Key.

    Uses AES-256-GCM (same primitive as data encryption).
    The output format is: nonce (12 bytes) || wrapped_ciphertext
    This is stored in KeyMetadata.encrypted_key.

    The nonce is prepended to the ciphertext so the stored blob is self-contained.
    No AAD is used here because the key_id in KeyMetadata already binds identity.

    Args:
        dek: 32-byte plaintext Data Encryption Key to wrap.
        mek: 32-byte Master Encryption Key.

    Returns:
        nonce (12 bytes) || wrapped_ciphertext (32 bytes plaintext + 16 bytes tag = 48 bytes)
        Total: 60 bytes
    """
    if len(dek) != KEY_SIZE:
        raise ValueError(f"DEK must be {KEY_SIZE} bytes")
    if len(mek) != KEY_SIZE:
        raise ValueError(f"MEK must be {KEY_SIZE} bytes")

    blob = encrypt(dek, mek, aad=None)
    return blob.nonce + blob.ciphertext


def unwrap_key(wrapped: bytes, mek: bytes) -> bytes:
    """
    Decrypt (unwrap) a wrapped Data Encryption Key using the MEK.

    Args:
        wrapped: nonce (12) || wrapped_ciphertext (48), total 60 bytes
        mek:     32-byte Master Encryption Key.

    Returns:
        32-byte plaintext DEK.

    Raises:
        InvalidTag: If wrapped key is tampered or MEK is wrong.
    """
    if len(mek) != KEY_SIZE:
        raise ValueError(f"MEK must be {KEY_SIZE} bytes")
    if len(wrapped) < NONCE_SIZE + KEY_SIZE + TAG_SIZE:
        raise ValueError("Wrapped key blob is too short")

    nonce = wrapped[:NONCE_SIZE]
    ciphertext = wrapped[NONCE_SIZE:]
    return decrypt(ciphertext, mek, nonce, aad=None)


def compute_checksum(plaintext: bytes, key: bytes) -> str:
    """
    Compute HMAC-SHA256 of plaintext as a hex string.

    Purpose: stored alongside ciphertext to verify decryption correctness
    without logging the plaintext.  After decryption, re-compute the checksum
    and compare with constant_time_compare() to detect silent corruption.

    Using HMAC (not plain SHA-256) prevents length-extension attacks and
    requires knowledge of the key to forge a valid checksum.
    """
    return hmac.new(key, plaintext, sha256).hexdigest()


def verify_checksum(plaintext: bytes, expected: str, key: bytes) -> bool:
    """
    Constant-time checksum verification to prevent timing oracle attacks.

    Returns True if checksum matches, False otherwise.
    NEVER raise on mismatch — let the caller decide the response.
    """
    actual = compute_checksum(plaintext, key)
    return constant_time_compare(actual, expected)


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison using hmac.compare_digest.

    Why constant-time?
    Regular string comparison short-circuits on the first differing byte.
    An attacker can measure response times to determine how many leading
    bytes of a secret match — a timing oracle attack.
    hmac.compare_digest always takes the same time regardless of where
    the strings differ.

    This function should be used for:
    - Token comparisons
    - Checksum comparisons
    - Any comparison involving secret data
    """
    return hmac.compare_digest(a.encode() if isinstance(a, str) else a,
                               b.encode() if isinstance(b, str) else b)


def build_aad(secret_id: str, version: int) -> bytes:
    """
    Build the Additional Authenticated Data for a secret version.

    Format: "secret_id:version" — simple, deterministic, unique per version.
    This binds each encrypted value to its exact (secret, version) identity.
    """
    return f"{secret_id}:{version}".encode("utf-8")
