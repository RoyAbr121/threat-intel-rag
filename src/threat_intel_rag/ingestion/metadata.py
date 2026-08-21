from __future__ import annotations

import re
from collections import defaultdict

from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from threat_intel_rag.config import settings
from threat_intel_rag.db.models import IngestionRecord
from threat_intel_rag.ingestion.qdrant_setup import (
    COLLECTION_NAME,
    HYBRID_COLLECTION_NAME,
    get_client,
)

_CVSS_RE = re.compile(r"CVSS:\s*(\d+(?:\.\d+)?)\s+([A-Z]+)")
_BATCH = 512
_SCROLL = 4096


def backfill_cvss() -> tuple[int, int]:
    """Lift CVSS out of the text blob into structured, filterable payload.

    Score/severity has ~100 distinct values across 185k records, so we group
    CVE IDs by value and issue one set_payload per group rather than one per
    point. Records with no CVSS v3.1 metric simply keep no field.
    """
    client = get_client()
    groups: dict[tuple[float, str], list[str]] = defaultdict(list)
    scanned = 0
    offset = None

    while True:
        points, offset = client.scroll(
            collection_name=HYBRID_COLLECTION_NAME,
            limit=_SCROLL,
            offset=offset,
            with_payload=["cve_id", "text"],
            with_vectors=False,
        )

        for point in points:
            payload = point.payload or {}
            scanned += 1
            match = _CVSS_RE.search(str(payload.get("text", "")))

            if match:
                score, severity = float(match.group(1)), match.group(2)
                groups[(score, severity)].append(str(payload["cve_id"]))

        if offset is None:
            break

    stamped = 0

    for (score, severity), cve_ids in groups.items():
        for i in range(0, len(cve_ids), _BATCH):
            batch = cve_ids[i : i + _BATCH]
            client.set_payload(
                collection_name=HYBRID_COLLECTION_NAME,
                payload={"cvss_score": score, "cvss_severity": severity},
                points=Filter(
                    must=[FieldCondition(key="cve_id", match=MatchAny(any=batch))]
                ),
            )
            stamped += len(batch)

    return scanned, stamped


# the unpinned name every record was written with before Step 4.3b; the
# pinned tag has an identical digest, so this is a relabel, not a change
_LEGACY_EMBED_MODEL = "nomic-embed-text"

# one filtered update covering all 185k points is a single request the server
# answers only when it has finished; the query path's fail-fast default gives
# up on it long before then
_MAINTENANCE_TIMEOUT = 600


def _relabel_collection(client: QdrantClient, name: str, new: str) -> int:
    matches_legacy = Filter(
        must=[
            FieldCondition(
                key="embed_model", match=MatchValue(value=_LEGACY_EMBED_MODEL)
            )
        ]
    )
    found = client.count(
        collection_name=name, count_filter=matches_legacy, exact=True
    ).count

    if found:
        client.set_payload(
            collection_name=name, payload={"embed_model": new}, points=matches_legacy
        )

    return found


async def relabel_embed_model() -> tuple[int, int, int]:
    """Rewrite the old unpinned embed-model label to the pinned tag.

    No vector is recomputed. Step 4.3b's digest check proved the pinned tag
    names the same model that produced these vectors, so only the label moves
    - which keeps pipeline.py's "already embedded by the current model?" test
    working instead of marking all 185k records stale. Safe to re-run: a
    second run matches nothing.
    """
    new = settings.ollama_embed_model
    client = get_client(timeout=_MAINTENANCE_TIMEOUT)
    baseline = _relabel_collection(client, COLLECTION_NAME, new)
    hybrid = _relabel_collection(client, HYBRID_COLLECTION_NAME, new)

    engine = create_async_engine(settings.postgres_dsn)

    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        # count first, then write - the same shape as the Qdrant half above,
        # and it avoids session.execute()'s declared Result type, which has no
        # rowcount (only the DML-specific CursorResult does)
        rows = (
            await session.execute(
                select(func.count())
                .select_from(IngestionRecord)
                .where(IngestionRecord.embed_model == _LEGACY_EMBED_MODEL)
            )
        ).scalar_one()

        if rows:
            await session.execute(
                update(IngestionRecord)
                .where(IngestionRecord.embed_model == _LEGACY_EMBED_MODEL)
                .values(embed_model=new)
            )
            await session.commit()

    await engine.dispose()

    return baseline, hybrid, rows
