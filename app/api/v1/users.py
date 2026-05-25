"""User management endpoints — admin only."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_scope
from app.db.session import get_db
from app.domain.enums import Scope, UserRole
from app.domain.schemas.auth import TokenPayload
from app.domain.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services.user_service import (
    PrivilegeEscalationError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UserService,
)

router = APIRouter(prefix="/users", tags=["Users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope(Scope.USERS_WRITE))],
    summary="Create a new user (admin+)",
)
async def create_user(
    payload: UserCreate,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    svc = UserService(db)
    try:
        return await svc.create_user(
            payload=payload,
            actor_id=token.sub,
            actor_username=token.username,
            actor_role=UserRole(token.role),
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
        )
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except PrivilegeEscalationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get(
    "",
    response_model=UserListResponse,
    dependencies=[Depends(require_scope(Scope.USERS_READ))],
    summary="List all users (admin+)",
)
async def list_users(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    role: UserRole | None = None,
    is_active: bool | None = None,
    db: AsyncSession = Depends(get_db),
) -> UserListResponse:
    svc = UserService(db)
    return await svc.list_users(page=page, page_size=page_size, role=role, is_active=is_active)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    svc = UserService(db)
    return await svc.get_user(uuid.UUID(token.sub))


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_scope(Scope.USERS_READ))],
    summary="Get a specific user (admin+)",
)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    svc = UserService(db)
    try:
        return await svc.get_user(user_id)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_scope(Scope.USERS_WRITE))],
    summary="Update a user (admin+)",
)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    svc = UserService(db)
    try:
        return await svc.update_user(
            user_id=user_id,
            payload=payload,
            actor_id=token.sub,
            actor_username=token.username,
            actor_role=UserRole(token.role),
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
        )
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except PrivilegeEscalationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
