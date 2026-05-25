"""
Role-Based Access Control (RBAC) permission checking.

Design:
- Permissions defined as sets of Scope values per role (in enums.py)
- FastAPI dependencies (in dependencies.py) call require_scopes() to enforce
- Privilege escalation protection: a user cannot grant a role higher than their own
- All denials are logged to the audit log

Scope checking philosophy:
- Prefer explicit scope requirements over role checks in endpoints
- Roles determine the initial scope set; future versions may allow custom scopes
- Use least-privilege: request only the scope(s) an endpoint actually needs
"""

from __future__ import annotations

from app.domain.enums import ROLE_SCOPES, Scope, UserRole
from app.domain.schemas.auth import TokenPayload


def has_scope(token: TokenPayload, scope: Scope) -> bool:
    """Check if a token carries a specific scope."""
    return scope.value in token.scopes


def has_any_scope(token: TokenPayload, *scopes: Scope) -> bool:
    """Check if a token carries at least one of the given scopes."""
    token_scopes = set(token.scopes)
    return any(s.value in token_scopes for s in scopes)


def has_all_scopes(token: TokenPayload, *scopes: Scope) -> bool:
    """Check if a token carries all of the given scopes."""
    token_scopes = set(token.scopes)
    return all(s.value in token_scopes for s in scopes)


def can_assign_role(assigner_role: UserRole, target_role: UserRole) -> bool:
    """
    Privilege escalation check: can `assigner_role` assign `target_role`?

    Rules:
    - super_admin can assign any role
    - admin can assign up to admin (not super_admin)
    - developer/readonly cannot assign roles
    """
    if assigner_role == UserRole.SUPER_ADMIN:
        return True
    if assigner_role == UserRole.ADMIN:
        return target_role in {UserRole.READONLY, UserRole.DEVELOPER, UserRole.ADMIN}
    return False


def get_scopes_for_role(role: UserRole) -> list[str]:
    """Return the list of scope strings for a given role."""
    return [s.value for s in ROLE_SCOPES.get(role, frozenset())]


class PermissionDenied(Exception):
    """
    Raised when a permission check fails.

    Carries enough context for the audit logger to record a meaningful
    AUTHZ_DENIED event without the endpoint needing to know the details.
    """

    def __init__(self, actor_id: str, required_scope: Scope, resource: str = "") -> None:
        self.actor_id = actor_id
        self.required_scope = required_scope
        self.resource = resource
        super().__init__(
            f"Actor {actor_id!r} lacks scope {required_scope.value!r}"
            + (f" for resource {resource!r}" if resource else "")
        )
