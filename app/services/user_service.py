"""User management service."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.auth.rbac import can_assign_role
from app.crypto.argon2_utils import hash_password
from app.domain.enums import AuditEventType, AuditResult, ResourceType, UserRole
from app.domain.models.user import User
from app.domain.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.repositories.user_repository import UserRepository


class UserAlreadyExistsError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class PrivilegeEscalationError(Exception):
    pass


class UserService:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._user_repo = UserRepository(db)
        self._audit = AuditLogger(db)

    async def create_user(
        self,
        payload: UserCreate,
        actor_id: str,
        actor_username: str,
        actor_role: UserRole,
        request_id: str | None = None,
        ip_address: str | None = None,
    ) -> UserResponse:
        if not can_assign_role(actor_role, payload.role):
            raise PrivilegeEscalationError(
                f"Role {actor_role.value} cannot assign role {payload.role.value}"
            )

        if await self._user_repo.username_exists(payload.username):
            raise UserAlreadyExistsError(f"Username '{payload.username}' is already taken")
        if await self._user_repo.email_exists(payload.email):
            raise UserAlreadyExistsError(f"Email '{payload.email}' is already registered")

        user = User(
            id=uuid.uuid4(),
            username=payload.username,
            email=payload.email,
            password_hash=hash_password(payload.password),
            role=payload.role,
        )
        await self._user_repo.create(user)

        await self._audit.emit(
            event_type=AuditEventType.USER_CREATE,
            action="create",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.USER,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(user.id),
            request_id=request_id,
            ip_address=ip_address,
            details={"username": payload.username, "role": payload.role.value},
        )

        return UserResponse.model_validate(user)

    async def update_user(
        self,
        user_id: uuid.UUID,
        payload: UserUpdate,
        actor_id: str,
        actor_username: str,
        actor_role: UserRole,
        request_id: str | None = None,
        ip_address: str | None = None,
    ) -> UserResponse:
        user = await self._user_repo.get(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        changes: dict = {}

        if payload.role is not None:
            if not can_assign_role(actor_role, payload.role):
                raise PrivilegeEscalationError(
                    f"Role {actor_role.value} cannot assign role {payload.role.value}"
                )
            old_role = user.role
            user.role = payload.role
            changes["role"] = {"from": old_role, "to": payload.role.value}

        if payload.email is not None:
            user.email = payload.email
            changes["email"] = True

        if payload.is_active is not None:
            user.is_active = payload.is_active
            changes["is_active"] = payload.is_active

        if payload.is_locked is not None:
            user.is_locked = payload.is_locked
            if not payload.is_locked:
                user.failed_login_attempts = 0
                user.locked_until = None
            changes["is_locked"] = payload.is_locked

        await self._audit.emit(
            event_type=AuditEventType.USER_UPDATE,
            action="update",
            result=AuditResult.SUCCESS,
            resource_type=ResourceType.USER,
            actor_id=actor_id,
            actor_username=actor_username,
            resource_id=str(user_id),
            request_id=request_id,
            ip_address=ip_address,
            details=changes,
        )

        return UserResponse.model_validate(user)

    async def list_users(
        self,
        page: int = 1,
        page_size: int = 50,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> UserListResponse:
        users, total = await self._user_repo.list_users(
            page=page, page_size=page_size, role=role, is_active=is_active
        )
        return UserListResponse(
            items=[UserResponse.model_validate(u) for u in users],
            total=total,
            page=page,
            page_size=page_size,
        )

    async def get_user(self, user_id: uuid.UUID) -> UserResponse:
        user = await self._user_repo.get(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        return UserResponse.model_validate(user)
