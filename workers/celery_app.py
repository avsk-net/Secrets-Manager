"""
Celery application factory with periodic task schedule.

Worker architecture:
  - Celery workers run as separate processes (docker-compose: worker service)
  - Broker: Redis (same cluster as rate limiting, different DB)
  - Result backend: Redis
  - Beat scheduler: runs periodic cleanup/maintenance tasks

Why Celery over RQ?
  - Periodic task scheduling via celery-beat (RQ requires separate cron)
  - Better retry/error handling primitives (max_retries, countdown)
  - Mature ecosystem with good async task support
  - However: RQ is simpler if you don't need periodic tasks

Task isolation:
  Each task creates its own DB session — workers are completely stateless.
  This allows horizontal scaling of workers independently of API nodes.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "secret_manager",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["workers.tasks"],
)

celery_app.conf.update(
    # Serialization: JSON for portability; avoid pickle (arbitrary code execution)
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Timezone: always UTC in distributed systems
    timezone="UTC",
    enable_utc=True,
    # Retry behavior
    task_acks_late=True,          # ACK after task completes (not when received)
    task_reject_on_worker_lost=True,  # Requeue if worker dies mid-task
    # Concurrency: use threads for I/O-bound tasks (DB/Redis)
    worker_concurrency=4,
    # Prefetch: don't hoard tasks (allows other workers to pick them up)
    worker_prefetch_multiplier=1,
    # Result TTL: keep results for 1 hour
    result_expires=3600,
    # Beat schedule: periodic maintenance tasks
    beat_schedule={
        "cleanup-expired-tokens": {
            "task": "workers.tasks.cleanup_expired_tokens",
            "schedule": crontab(minute="*/15"),  # Every 15 minutes
        },
        "rotate-old-deks": {
            "task": "workers.tasks.rotate_old_deks",
            "schedule": crontab(hour="2", minute="0"),  # Daily at 02:00 UTC
        },
        "health-check": {
            "task": "workers.tasks.worker_health_check",
            "schedule": crontab(minute="*/5"),  # Every 5 minutes
        },
    },
)
