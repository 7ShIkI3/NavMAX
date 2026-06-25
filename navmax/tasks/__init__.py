"""Task queue Celery pour NavMAX — scans longue durée en background."""
from celery import Celery

celery_app = Celery(
    "navmax",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    task_always_eager=False,  # dev mode: False = Redis required, True = sync eager
)

__all__ = ["celery_app"]
