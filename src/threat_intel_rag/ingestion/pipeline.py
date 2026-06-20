from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime

import httpx
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from threat_intel_rag.config import settings
from threat_intel_rag.db.models import IngestionRecord, IngestionStatus
from threat_intel_rag.ingestion.nvd_client import CveDetail, NvdClient
from threat_intel_rag.ingestion.qdrant_setup import COLLECTION_NAME


def normalize_cve(cve: CveDetail) -> str | None:
    description = next((d.value for d in cve.descriptions if d.lang == "en"), None)

    if not description:
        return None

    severity = ""

    if cve.metrics.cvss_metric_v31:
        m = cve.metrics.cvss_metric_v31[0]
        severity = f" CVSS: {m.cvss_data.base_score} {m.cvss_data.base_severity}"

    return f"{cve.id}{severity}\n{description}"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def cve_id_to_point_id(cve_id: str) -> int:
    digest = hashlib.sha256(cve_id.encode()).digest()
    return int(struct.unpack(">Q", digest[:8])[0])


async def embed(text: str) -> list[float]:
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{settings.ollama_base_url}/api/embeddings",
            json={"model": settings.ollama_embed_model, "prompt": text},
        )

        response.raise_for_status()

        return list(response.json()["embedding"])


async def ingest_cves(
    limit: int | None = None, start_date: datetime | None = None
) -> None:
    engine = create_async_engine(settings.postgres_dsn)
    AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    qdrant = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)

    processed = 0

    async with NvdClient() as nvd:
        async for cve in nvd.iter_cves(start_date=start_date):
            if limit and processed >= limit:
                break

            text = normalize_cve(cve)

            if text is None:
                continue

            chash = content_hash(text)

            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(IngestionRecord).where(
                        IngestionRecord.source == "nvd",
                        IngestionRecord.external_id == cve.id,
                    )
                )

                record = result.scalar_one_or_none()

                if (
                    record
                    and record.content_hash == chash
                    and record.embed_model == settings.ollama_embed_model
                ):
                    continue

                vector = await embed(text)

                qdrant.upsert(
                    collection_name=COLLECTION_NAME,
                    points=[
                        PointStruct(
                            id=cve_id_to_point_id(cve.id),
                            vector=vector,
                            payload={
                                "cve_id": cve.id,
                                "source": "nvd",
                                "embed_model": settings.ollama_embed_model,
                                "published": cve.published.isoformat(),
                                "text": text,
                            },
                        )
                    ],
                )

                if record is None:
                    record = IngestionRecord(
                        source="nvd",
                        external_id=cve.id,
                        content_hash=chash,
                        embed_model=settings.ollama_embed_model,
                        status=IngestionStatus.indexed,
                        indexed_at=datetime.now(UTC),
                    )

                    session.add(record)
                else:
                    record.content_hash = chash
                    record.embed_model = settings.ollama_embed_model
                    record.status = IngestionStatus.indexed
                    record.indexed_at = datetime.now(UTC)

                await session.commit()

            processed += 1
