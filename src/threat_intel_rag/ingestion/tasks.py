from __future__ import annotations

import asyncio

from celery import Celery, Task

from threat_intel_rag.config import settings
from threat_intel_rag.ingestion.pipeline import ingest_cves

celery_app = Celery(
    "threat_intel_rag",
    broker=settings.rabbitmq_url,
    backend="rpc://",
)


def run_nvd_ingestion(self: Task, limit: int | None = None) -> str:
    try:
        asyncio.run(ingest_cves(limit=limit))
        return "ok"
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60) from exc
