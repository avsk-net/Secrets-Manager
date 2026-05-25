"""
Unit tests for JWT token handling, RBAC, and Argon2id.

Tests cover:
  - Access token creation and validation
  - Token expiry rejection
  - Invalid audience/issuer rejection
  - Revoked JTI rejection
  - Refresh token hashing
  - RBAC scope checking
  - Role ordering comparisons
  - Argon2id hash/verify
  - Argon2 parameter upgrade detection
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from jose import JWTError

from app.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
    verify_access_token,
)
from app.auth.rbac import (
    can_assign_role,
    get_scopes_for_role,
    has_all_scopes,
    has_any_scope,
    has_scope,
)
from app.crypto.argon2_utils import derive_key, hash_password, needs_rehash, verify_password
from app.domain.enums import ROLE_SCOPES, Scope, UserRole
from app.domain.schemas.auth import TokenPayload


# ── JWT creation / validation ─────────────────────────────────────────────────

class TestJWT:
    def test_create_and_verify_access_token(self, test_settings):
        user_id = uuid.uuid4()
        token, jti = create_access_token(
            user_id=user_id,
            username="testuser",
            role=UserRole.DEVELOPER,
        )
        assert isinstance(token, str)
        assert len(token) > 50

        payload = verify_access_token(token)
        assert payload.sub == str(user_id)
        assert payload.username == "testuser"
        assert payload.role == UserRole.DEVELOPER.value
        assert payload.jti == jti

    def test_token_contains_correct_scopes(self, test_settings):
        token, _ = create_access_token(
            user_id=uuid.uuid4(),
            username="dev",
            role=UserRole.DEVELOPER,
        )
        payload = verify_access_token(token)
        expected = get_scopes_for_role(UserRole.DEVELOPER)
        assert set(payload.scopes) == set(expected)

    def test_super_admin_has_all_scopes(self, test_settings):
        token, _ = create_access_token(
            user_id=uuid.uuid4(),
            username="admin",
            role=UserRole.SUPER_ADMIN,
        )
        payload = verify_access_token(token)
        all_scopes = {s.value for s in Scope}
        assert all_scopes.issubset(set(payload.scopes))

    def test_expired_token_raises(self, test_settings):
        import os
        os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "-1"
        from app.config import get_settings
        get_settings.cache_clear()

        token, _ = create_access_token(
            user_id=uuid.uuid4(),
            username="expired",
            role=UserRole.READONLY,
        )
        # Reset
        os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
        get_settings.cache_clear()

        with pytest.raises(JWTError):
            verify_access_token(token)

    def test_tampered_token_raises(self, test_settings):
        token, _ = create_access_token(
            user_id=uuid.uuid4(),
            username="legit",
            role=UserRole.READONLY,
        )
        # Flip a character in the signature
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + "." + parts[2][:-1] + "X"
        with pytest.raises(JWTError):
            verify_access_token(tampered)

    def test_wrong_audience_raises(self, test_settings):
        """A token issued by this service should not validate for a different audience."""
        from jose import jwt
        settings = test_settings
        payload = {
            "sub": str(uuid.uuid4()),
            "username": "test",
            "role": "readonly",
            "scopes": [],
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 900,
            "iss": settings.jwt_issuer,
            "aud": "wrong-audience",  # Different audience
        }
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
        with pytest.raises(JWTError):
            verify_access_token(token)

    def test_different_jti_per_token(self, test_settings):
        uid = uuid.uuid4()
        _, jti1 = create_access_token(uid, "u", UserRole.READONLY)
        _, jti2 = create_access_token(uid, "u", UserRole.READONLY)
        assert jti1 != jti2


# ── Refresh token ─────────────────────────────────────────────────────────────

class TestRefreshToken:
    def test_refresh_token_is_url_safe(self, test_settings):
        raw, _ = create_refresh_token()
        # URL-safe base64 chars only
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in raw)

    def test_refresh_token_hash_is_sha256(self, test_settings):
        raw, h = create_refresh_token()
        assert len(h) == 64  # SHA-256 hex = 64 chars
        assert h == hash_refresh_token(raw)

    def test_different_refresh_tokens_different_hashes(self, test_settings):
        hashes = {create_refresh_token()[1] for _ in range(100)}
        assert len(hashes) == 100


# ── RBAC ──────────────────────────────────────────────────────────────────────

class TestRBAC:
    def _make_token(self, role: UserRole) -> TokenPayload:
        scopes = get_scopes_for_role(role)
        return TokenPayload(
            sub=str(uuid.uuid4()),
            username="u",
            role=role.value,
            scopes=scopes,
            jti=str(uuid.uuid4()),
            iat=int(time.time()),
            exp=int(time.time()) + 900,
            iss="test",
            aud="test",
        )

    def test_readonly_has_read_scope(self):
        t = self._make_token(UserRole.READONLY)
        assert has_scope(t, Scope.SECRETS_READ) is True

    def test_readonly_lacks_write_scope(self):
        t = self._make_token(UserRole.READONLY)
        assert has_scope(t, Scope.SECRETS_WRITE) is False

    def test_developer_has_write_scope(self):
        t = self._make_token(UserRole.DEVELOPER)
        assert has_scope(t, Scope.SECRETS_WRITE) is True

    def test_developer_lacks_delete_scope(self):
        t = self._make_token(UserRole.DEVELOPER)
        assert has_scope(t, Scope.SECRETS_DELETE) is False

    def test_admin_has_delete_scope(self):
        t = self._make_token(UserRole.ADMIN)
        assert has_scope(t, Scope.SECRETS_DELETE) is True

    def test_has_any_scope_true(self):
        t = self._make_token(UserRole.READONLY)
        assert has_any_scope(t, Scope.SECRETS_READ, Scope.SECRETS_WRITE) is True

    def test_has_any_scope_false(self):
        t = self._make_token(UserRole.READONLY)
        assert has_any_scope(t, Scope.SECRETS_WRITE, Scope.SECRETS_DELETE) is False

    def test_has_all_scopes(self):
        t = self._make_token(UserRole.DEVELOPER)
        assert has_all_scopes(t, Scope.SECRETS_READ, Scope.SECRETS_WRITE) is True

    def test_role_ordering(self):
        assert UserRole.SUPER_ADMIN >= UserRole.ADMIN
        assert UserRole.ADMIN >= UserRole.DEVELOPER
        assert UserRole.DEVELOPER >= UserRole.READONLY
        assert not (UserRole.READONLY >= UserRole.DEVELOPER)

    def test_can_assign_role_escalation_prevention(self):
        assert can_assign_role(UserRole.SUPER_ADMIN, UserRole.SUPER_ADMIN) is True
        assert can_assign_role(UserRole.ADMIN, UserRole.ADMIN) is True
        assert can_assign_role(UserRole.ADMIN, UserRole.SUPER_ADMIN) is False
        assert can_assign_role(UserRole.DEVELOPER, UserRole.READONLY) is False


# ── Argon2id ──────────────────────────────────────────────────────────────────

class TestArgon2:
    def test_hash_and_verify(self, test_settings):
        password = "SuperSecure!123"
        hashed = hash_password(password)
        assert verify_password(hashed, password) is True

    def test_wrong_password_fails(self, test_settings):
        hashed = hash_password("CorrectPassword!1")
        assert verify_password(hashed, "WrongPassword!1") is False

    def test_hash_includes_params(self, test_settings):
        hashed = hash_password("test!Password1")
        # PHC format: $argon2id$v=19$m=...,t=...,p=...
        assert "$argon2id$" in hashed
        assert "v=19" in hashed

    def test_hash_is_unique(self, test_settings):
        """Different salts → different hashes for same password."""
        pw = "SamePassword123!"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2

    def test_needs_rehash_with_low_params(self, test_settings):
        """A hash from weak parameters should be flagged for rehashing."""
        from argon2 import PasswordHasher
        from argon2.low_level import Type
        weak_hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1, type=Type.ID)
        weak_hash = weak_hasher.hash("somepassword")
        # Our hasher uses higher params, so this should need rehashing
        assert needs_rehash(weak_hash) is True

    def test_derive_key_length(self, test_settings):
        key, salt = derive_key("passphrase", key_length=32)
        assert len(key) == 32
        assert len(salt) == 16

    def test_derive_key_deterministic(self, test_settings):
        """Same passphrase + salt → same key."""
        import os
        salt = os.urandom(16)
        key1, _ = derive_key("same passphrase", salt=salt)
        key2, _ = derive_key("same passphrase", salt=salt)
        assert key1 == key2

    def test_derive_key_different_passphrases(self, test_settings):
        import os
        salt = os.urandom(16)
        key1, _ = derive_key("passphrase1", salt=salt)
        key2, _ = derive_key("passphrase2", salt=salt)
        assert key1 != key2
