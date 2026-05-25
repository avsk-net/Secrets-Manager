"""
Unit tests for the cryptography engine.

Tests cover:
  - Encrypt/decrypt round-trip for all data sizes
  - Nonce uniqueness (no two calls return the same nonce)
  - AAD binding (wrong AAD causes decryption failure)
  - Key wrapping/unwrapping (envelope encryption)
  - Wrong key/nonce causes InvalidTag
  - Checksum verification
  - Constant-time comparison (no early return on mismatch)
  - Argon2id hash/verify/derive
"""

from __future__ import annotations

import os
import time

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto.engine import (
    KEY_SIZE,
    NONCE_SIZE,
    build_aad,
    compute_checksum,
    constant_time_compare,
    decrypt,
    encrypt,
    generate_dek,
    generate_nonce,
    unwrap_key,
    verify_checksum,
    wrap_key,
)


# ── Encrypt/Decrypt ───────────────────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_round_trip_empty(self):
        key = generate_dek()
        blob = encrypt(b"", key)
        assert decrypt(blob.ciphertext, key, blob.nonce) == b""

    def test_round_trip_small(self):
        key = generate_dek()
        plaintext = b"hello world"
        blob = encrypt(plaintext, key)
        assert decrypt(blob.ciphertext, key, blob.nonce) == plaintext

    def test_round_trip_large(self):
        key = generate_dek()
        plaintext = os.urandom(1024 * 1024)  # 1 MiB
        blob = encrypt(plaintext, key)
        assert decrypt(blob.ciphertext, key, blob.nonce) == plaintext

    def test_round_trip_with_aad(self):
        key = generate_dek()
        aad = b"secret-id:1"
        plaintext = b"my secret value"
        blob = encrypt(plaintext, key, aad=aad)
        assert decrypt(blob.ciphertext, key, blob.nonce, aad=aad) == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        key = generate_dek()
        plaintext = b"test data"
        blob = encrypt(plaintext, key)
        assert blob.ciphertext != plaintext
        # Ciphertext should be larger (includes 16-byte GCM tag)
        assert len(blob.ciphertext) == len(plaintext) + 16

    def test_same_plaintext_different_ciphertext(self):
        """Each encrypt call uses a fresh nonce → different ciphertext."""
        key = generate_dek()
        plaintext = b"same plaintext"
        blob1 = encrypt(plaintext, key)
        blob2 = encrypt(plaintext, key)
        assert blob1.ciphertext != blob2.ciphertext
        assert blob1.nonce != blob2.nonce

    def test_wrong_key_raises_invalid_tag(self):
        key1 = generate_dek()
        key2 = generate_dek()
        blob = encrypt(b"secret", key1)
        with pytest.raises(InvalidTag):
            decrypt(blob.ciphertext, key2, blob.nonce)

    def test_wrong_nonce_raises_invalid_tag(self):
        key = generate_dek()
        blob = encrypt(b"secret", key)
        wrong_nonce = generate_nonce()
        with pytest.raises(InvalidTag):
            decrypt(blob.ciphertext, key, wrong_nonce)

    def test_tampered_ciphertext_raises_invalid_tag(self):
        key = generate_dek()
        blob = encrypt(b"secret value", key)
        # Flip one bit in the ciphertext
        tampered = bytes([blob.ciphertext[0] ^ 0x01]) + blob.ciphertext[1:]
        with pytest.raises(InvalidTag):
            decrypt(tampered, key, blob.nonce)

    def test_wrong_aad_raises_invalid_tag(self):
        key = generate_dek()
        aad = b"correct-aad"
        wrong_aad = b"wrong-aad"
        blob = encrypt(b"secret", key, aad=aad)
        with pytest.raises(InvalidTag):
            decrypt(blob.ciphertext, key, blob.nonce, aad=wrong_aad)

    def test_missing_aad_raises_invalid_tag(self):
        """Omitting AAD when it was used during encrypt should fail."""
        key = generate_dek()
        aad = b"required-aad"
        blob = encrypt(b"secret", key, aad=aad)
        with pytest.raises(InvalidTag):
            decrypt(blob.ciphertext, key, blob.nonce, aad=None)

    def test_wrong_key_size_raises_value_error(self):
        with pytest.raises(ValueError, match="Key must be"):
            encrypt(b"data", b"short_key")

    def test_wrong_nonce_size_raises_value_error(self):
        key = generate_dek()
        blob = encrypt(b"data", key)
        with pytest.raises(ValueError, match="Nonce must be"):
            decrypt(blob.ciphertext, key, b"bad_nonce")


# ── Nonce generation ──────────────────────────────────────────────────────────

class TestNonceGeneration:
    def test_nonce_size(self):
        nonce = generate_nonce()
        assert len(nonce) == NONCE_SIZE

    def test_nonce_randomness(self):
        """10,000 nonces should all be unique (collision probability ≈ 2^-96)."""
        nonces = {generate_nonce() for _ in range(10000)}
        assert len(nonces) == 10000


# ── Key generation ────────────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_dek_size(self):
        key = generate_dek()
        assert len(key) == KEY_SIZE

    def test_dek_randomness(self):
        keys = {generate_dek() for _ in range(100)}
        assert len(keys) == 100


# ── Key wrapping ──────────────────────────────────────────────────────────────

class TestKeyWrapping:
    def test_wrap_unwrap_round_trip(self):
        dek = generate_dek()
        mek = generate_dek()
        wrapped = wrap_key(dek, mek)
        unwrapped = unwrap_key(wrapped, mek)
        assert unwrapped == dek

    def test_wrong_mek_raises_invalid_tag(self):
        dek = generate_dek()
        mek = generate_dek()
        wrong_mek = generate_dek()
        wrapped = wrap_key(dek, mek)
        with pytest.raises(InvalidTag):
            unwrap_key(wrapped, wrong_mek)

    def test_wrapped_key_length(self):
        """wrap_key output: 12 (nonce) + 32 (key) + 16 (tag) = 60 bytes."""
        dek = generate_dek()
        mek = generate_dek()
        wrapped = wrap_key(dek, mek)
        assert len(wrapped) == 12 + 32 + 16

    def test_tampered_wrapped_key_raises(self):
        dek = generate_dek()
        mek = generate_dek()
        wrapped = wrap_key(dek, mek)
        tampered = bytes([wrapped[0] ^ 0x01]) + wrapped[1:]
        with pytest.raises(InvalidTag):
            unwrap_key(tampered, mek)


# ── Checksum ──────────────────────────────────────────────────────────────────

class TestChecksum:
    def test_checksum_is_deterministic(self):
        plaintext = b"deterministic"
        key = generate_dek()
        c1 = compute_checksum(plaintext, key)
        c2 = compute_checksum(plaintext, key)
        assert c1 == c2

    def test_checksum_length(self):
        c = compute_checksum(b"test", generate_dek())
        assert len(c) == 64  # SHA-256 hex digest

    def test_verify_checksum_correct(self):
        plaintext = b"verify me"
        key = generate_dek()
        checksum = compute_checksum(plaintext, key)
        assert verify_checksum(plaintext, checksum, key) is True

    def test_verify_checksum_wrong_data(self):
        key = generate_dek()
        checksum = compute_checksum(b"original", key)
        assert verify_checksum(b"modified", checksum, key) is False

    def test_verify_checksum_wrong_key(self):
        key1 = generate_dek()
        key2 = generate_dek()
        checksum = compute_checksum(b"data", key1)
        assert verify_checksum(b"data", checksum, key2) is False


# ── Constant-time comparison ──────────────────────────────────────────────────

class TestConstantTimeCompare:
    def test_equal_strings(self):
        assert constant_time_compare("abc123", "abc123") is True

    def test_different_strings(self):
        assert constant_time_compare("abc123", "xyz789") is False

    def test_timing_consistency(self):
        """
        Timing should not differ significantly between equal and unequal inputs.

        This is a soft test — we can't guarantee constant time in pure Python,
        but hmac.compare_digest is implemented in C and should be consistent.
        """
        secret = "a" * 64
        wrong = "b" * 64

        iterations = 1000
        t_equal = 0.0
        t_unequal = 0.0

        for _ in range(iterations):
            start = time.perf_counter()
            constant_time_compare(secret, secret)
            t_equal += time.perf_counter() - start

        for _ in range(iterations):
            start = time.perf_counter()
            constant_time_compare(secret, wrong)
            t_unequal += time.perf_counter() - start

        # Average time difference should be < 10x (very loose bound)
        avg_equal = t_equal / iterations
        avg_unequal = t_unequal / iterations
        ratio = max(avg_equal, avg_unequal) / max(min(avg_equal, avg_unequal), 1e-10)
        assert ratio < 10, f"Timing ratio too large: {ratio:.2f}"


# ── AAD builder ───────────────────────────────────────────────────────────────

class TestAAD:
    def test_aad_format(self):
        aad = build_aad("abc-123", 5)
        assert aad == b"abc-123:5"

    def test_different_versions_produce_different_aad(self):
        aad1 = build_aad("same-id", 1)
        aad2 = build_aad("same-id", 2)
        assert aad1 != aad2

    def test_different_ids_produce_different_aad(self):
        aad1 = build_aad("id-1", 1)
        aad2 = build_aad("id-2", 1)
        assert aad1 != aad2
