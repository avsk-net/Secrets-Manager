"""
Celery background tasks for maintenance operations.

Tasks:
  cleanup_expired_tokens:  Delete expired refresh tokens from DB
  rotate_old_deks:         Rotate DEKs older than MAX_DEK_AGE_DAYS
  worker_health_check:     Emit a heartbeat event to confirm workers are running
  invalidate_secret_cache: Targeted cache invalidation (triggered by events)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import structlog
from celery import Task
from sqlalchemy.ext.asyncio import AsyncSession

from workers.celery_app import celery_app

log = structlog.get_logger(__name__)

MAX_DEK_AGE_DAYS = 90  # Rotate DEKs older than 90 days


def _run_async(coro) -> None:
    """Run an async coroutine in a new event loop (Celery tasks are sync)."""
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    name="workers.tasks.cleanup_expired_tokens",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def cleanup_expired_tokens(self: Task) -> dict:
    """Delete expired refresh tokens — prevents unbounded DB growth."""

    async def _run():
        from app.db.session import get_session_factory
        from app.repositories.token_repository import TokenRepository

        factory = get_session_factory()
        async with factory() as session:
            repo = TokenRepository(session)
            deleted = await repo.delete_expired()
            await session.commit()
            log.info("cleanup_expired_tokens", deleted=deleted)
            return {"deleted": deleted}

    try:
        return _run_async(_run())
    except Exception as exc:
        log.error("cleanup_expired_tokens_failed", error=str(exc))
        raise self.retry(exc=exc)


@celery_app.task(
    name="workers.tasks.rotate_old_deks",
    bind=True,
    max_retries=1,
    default_retry_delay=300,
)
def rotate_old_deks(self: Task) -> dict:
    """
    Rotate DEKs older than MAX_DEK_AGE_DAYS.

    This is a scheduled rotation — not triggered by compromise.
    DEKs are rotated preventively to limit the window of exposure
    if a key were ever to be extracted from memory/swap.
    """

    async def _run():
        from sqlalchemy import select

        import redis.asyncio as aioredis

        from app.config import get_settings
        from app.crypto.key_management import KeyManagementService
        from app.db.session import get_session_factory
        from app.domain.models.secret import KeyMetadata

        settings = get_settings()
        factory = get_session_factory()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)

        cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_DEK_AGE_DAYS)
        rotated = 0

        try:
            async with factory() as session:
                stmt = select(KeyMetadata).where(
                    KeyMetadata.is_active == True,  # noqa: E712
                    KeyMetadata.created_at < cutoff,
                )
                result = await session.execute(stmt)
                old_keys = result.scalars().all()

                key_svc = KeyManagementService(session, redis_client)
                for key in old_keys:
                    await key_svc.rotate_dek(key, reason=f"scheduled_{MAX_DEK_AGE_DAYS}d_rotation")
                    rotated += 1

                await session.commit()
        finally:
            await redis_client.close()

        log.info("rotate_old_deks", rotated=rotated)
        return {"rotated": rotated}

    try:
        return _run_async(_run())
    except Exception as exc:
        log.error("rotate_old_deks_failed", error=str(exc))
        raise self.retry(exc=exc)


@celery_app.task(name="workers.tasks.worker_health_check")
def worker_health_check() -> dict:
    """Heartbeat task — confirms worker queue is processing."""
    log.info("worker_health_check", timestamp=datetime.now(timezone.utc).isoformat())
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@celery_app.task(name="workers.tasks.invalidate_secret_cache")
def invalidate_secret_cache(secret_id: str) -> dict:
    """Invalidate a specific secret's cache entry — called after writes."""

    async def _run():
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        try:
            key = f"secret:cache:{secret_id}"
            await redis_client.delete(key)
        finally:
            await redis_client.close()

    _run_async(_run())
    return {"invalidated": secret_id}
