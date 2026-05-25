"""
Domain enumerations — all business-domain enum types in one module.

Keeping enums centralized prevents circular imports and makes
the permission/scope system easy to audit in one place.
"""

from __future__ import annotations

from enum import Enum, unique


@unique
class UserRole(str, Enum):
    """
    RBAC roles in ascending privilege order.

    Using str mixin allows direct comparison with string values from JWT claims
    without an extra .value lookup, and ensures correct JSON serialization.
    """

    READONLY = "readonly"
    DEVELOPER = "developer"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

    def __ge__(self, other: "UserRole") -> bool:
        order = [self.READONLY, self.DEVELOPER, self.ADMIN, self.SUPER_ADMIN]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "UserRole") -> bool:
        order = [self.READONLY, self.DEVELOPER, self.ADMIN, self.SUPER_ADMIN]
        return order.index(self) > order.index(other)


@unique
class Scope(str, Enum):
    """
    Fine-grained permission scopes embedded in JWT access tokens.

    Scopes follow the pattern  resource:action  to make the permission
    model self-documenting.  New resources should follow this convention.
    """

    SECRETS_READ = "secrets:read"
    SECRETS_WRITE = "secrets:write"
    SECRETS_DELETE = "secrets:delete"
    SECRETS_LIST = "secrets:list"

    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    USERS_DELETE = "users:delete"

    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"

    KEYS_READ = "keys:read"
    KEYS_ROTATE = "keys:rotate"

    ADMIN_ALL = "admin:all"  # super_admin wildcard


# Maps each role to its allowed scopes.
# This is the single source of truth for what each role can do.
ROLE_SCOPES: dict[UserRole, frozenset[Scope]] = {
    UserRole.READONLY: frozenset(
        {
            Scope.SECRETS_READ,
            Scope.SECRETS_LIST,
        }
    ),
    UserRole.DEVELOPER: frozenset(
        {
            Scope.SECRETS_READ,
            Scope.SECRETS_WRITE,
            Scope.SECRETS_LIST,
        }
    ),
    UserRole.ADMIN: frozenset(
        {
            Scope.SECRETS_READ,
            Scope.SECRETS_WRITE,
            Scope.SECRETS_DELETE,
            Scope.SECRETS_LIST,
            Scope.USERS_READ,
            Scope.USERS_WRITE,
            Scope.AUDIT_READ,
            Scope.AUDIT_VERIFY,
            Scope.KEYS_READ,
        }
    ),
    UserRole.SUPER_ADMIN: frozenset(Scope),  # All scopes
}


@unique
class SecretType(str, Enum):
    """Type of secret payload stored."""

    KV = "kv"          # Simple key-value string
    JSON = "json"      # Structured JSON object
    BINARY = "binary"  # Arbitrary binary data, stored as base64


@unique
class AuditEventType(str, Enum):
    """
    Canonical event types for the append-only audit log.

    New event types must be added here and documented — this list
    serves as the inventory for forensic analysis.
    """

    # Authentication
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REFRESH = "auth.token.refresh"
    AUTH_TOKEN_REVOKED = "auth.token.revoked"
    AUTH_TOKEN_FAMILY_REVOKED = "auth.token.family_revoked"
    AUTH_ACCOUNT_LOCKED = "auth.account.locked"

    # Secrets
    SECRET_READ = "secret.read"
    SECRET_CREATE = "secret.create"
    SECRET_UPDATE = "secret.update"
    SECRET_DELETE = "secret.delete"
    SECRET_RESTORE = "secret.restore"
    SECRET_VERSION_READ = "secret.version.read"
    SECRET_ROLLBACK = "secret.rollback"

    # Users
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_ROLE_CHANGE = "user.role.change"

    # Authorization
    AUTHZ_DENIED = "authz.denied"

    # Keys
    KEY_ROTATION = "key.rotation"
    KEY_CREATE = "key.create"

    # System
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"


@unique
class AuditResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@unique
class ResourceType(str, Enum):
    SECRET = "secret"
    USER = "user"
    TOKEN = "token"
    KEY = "key"
    AUDIT = "audit"
    SYSTEM = "system"
