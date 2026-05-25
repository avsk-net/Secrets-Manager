"""
Secrets CRUD endpoints with versioning, rollback, and namespace support.

Endpoint summary:
  GET    /secrets                           — List secrets (no values)
  POST   /secrets                           — Create secret
  GET    /secrets/{id}                      — Read + decrypt current version
  PUT    /secrets/{id}                      — Update (creates new version)
  DELETE /secrets/{id}                      — Soft delete
  GET    /secrets/{id}/versions             — List all versions
  GET    /secrets/{id}/versions/{ver}       — Read specific version
  POST   /secrets/{id}/rollback             — Rollback to a previous version
  GET    /secrets/by-name/{ns}/{name}       — Read by name + namespace

Authorization:
  List/Read:   secrets:read + secrets:list
  Create/Update: secrets:write
  Delete:      secrets:delete
  Rollback:    secrets:write (produces new version)
"""

from __future__ import annotations

import uuid
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, get_redis, require_scope
from app.db.session import get_db
from app.domain.enums import Scope
from app.domain.schemas.auth import TokenPayload
from app.domain.schemas.secret import (
    RollbackRequest,
    SecretCreate,
    SecretListResponse,
    SecretResponse,
    SecretUpdate,
    SecretVersionResponse,
)
from app.repositories.secret_repository import SecretVersionRepository
from app.services.secret_service import (
    SecretAlreadyExistsError,
    SecretDecryptionError,
    SecretNotFoundError,
    SecretService,
)

router = APIRouter(prefix="/secrets", tags=["Secrets"])


def _meta(request: Request) -> dict:
    return {
        "ip_address": (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        ),
        "user_agent": request.headers.get("User-Agent"),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.get(
    "",
    response_model=SecretListResponse,
    dependencies=[Depends(require_scope(Scope.SECRETS_LIST))],
    summary="List secrets (metadata only, no values)",
)
async def list_secrets(
    namespace: Annotated[str | None, Query(max_length=255)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretListResponse:
    svc = SecretService(db, redis_client)
    return await svc.list_secrets(namespace=namespace, page=page, page_size=page_size)


@router.post(
    "",
    response_model=SecretResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope(Scope.SECRETS_WRITE))],
    summary="Create a new secret",
)
async def create_secret(
    payload: SecretCreate,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretResponse:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        return await svc.create_secret(
            payload=payload,
            actor_id=token.sub,
            actor_username=token.username,
            **meta,
        )
    except SecretAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.get(
    "/{secret_id}",
    response_model=SecretResponse,
    dependencies=[Depends(require_scope(Scope.SECRETS_READ))],
    summary="Read and decrypt the current version of a secret",
)
async def get_secret(
    secret_id: uuid.UUID,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretResponse:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        return await svc.get_secret(
            secret_id=secret_id,
            actor_id=token.sub,
            actor_username=token.username,
            **meta,
        )
    except SecretNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
    except SecretDecryptionError:
        # Don't expose decryption failure details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt secret",
        )


@router.put(
    "/{secret_id}",
    response_model=SecretResponse,
    dependencies=[Depends(require_scope(Scope.SECRETS_WRITE))],
    summary="Update a secret (creates new version)",
)
async def update_secret(
    secret_id: uuid.UUID,
    payload: SecretUpdate,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretResponse:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        return await svc.update_secret(
            secret_id=secret_id,
            payload=payload,
            actor_id=token.sub,
            actor_username=token.username,
            **meta,
        )
    except SecretNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")


@router.delete(
    "/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope(Scope.SECRETS_DELETE))],
    summary="Soft-delete a secret",
)
async def delete_secret(
    secret_id: uuid.UUID,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> None:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        await svc.delete_secret(
            secret_id=secret_id,
            actor_id=token.sub,
            actor_username=token.username,
            **meta,
        )
    except SecretNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")


@router.get(
    "/{secret_id}/versions",
    response_model=list[SecretVersionResponse],
    dependencies=[Depends(require_scope(Scope.SECRETS_READ))],
    summary="List all versions of a secret",
)
async def list_versions(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> list[SecretVersionResponse]:
    ver_repo = SecretVersionRepository(db)
    versions = await ver_repo.list_versions(secret_id)
    return [
        SecretVersionResponse(
            id=v.id,
            secret_id=v.secret_id,
            version=v.version,
            is_current=v.is_current,
            created_at=v.created_at,
            created_by_id=v.created_by_id,
            metadata=v.metadata_,
        )
        for v in versions
    ]


@router.get(
    "/{secret_id}/versions/{version}",
    response_model=SecretResponse,
    dependencies=[Depends(require_scope(Scope.SECRETS_READ))],
    summary="Read a specific version of a secret",
)
async def get_secret_version(
    secret_id: uuid.UUID,
    version: int,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretResponse:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        return await svc.get_secret(
            secret_id=secret_id,
            actor_id=token.sub,
            actor_username=token.username,
            version=version,
            **meta,
        )
    except SecretNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")


@router.post(
    "/{secret_id}/rollback",
    response_model=SecretResponse,
    dependencies=[Depends(require_scope(Scope.SECRETS_WRITE))],
    summary="Roll back to a previous version (creates a new version)",
)
async def rollback_secret(
    secret_id: uuid.UUID,
    body: RollbackRequest,
    request: Request,
    token: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: aioredis.Redis = Depends(get_redis),
) -> SecretResponse:
    meta = _meta(request)
    svc = SecretService(db, redis_client)
    try:
        return await svc.rollback_to_version(
            secret_id=secret_id,
            target_version=body.version,
            actor_id=token.sub,
            actor_username=token.username,
            **meta,
        )
    except SecretNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
