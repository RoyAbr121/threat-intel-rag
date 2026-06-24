from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from fastembed import SparseTextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct, Record, SparseVector

from threat_intel_rag.ingestion.pipeline import cve_id_to_point_id
from threat_intel_rag.ingestion.qdrant_setup import (
    COLLECTION_NAME,
    HYBRID_COLLECTION_NAME,
    get_client,
)

_BATCH = 256


def dump_corpus(path: str) -> int:
    """Scroll the baseline collection's payloads to a local JSONL file."""
    client = get_client()
    written = 0
    offset = None

    with Path(path).open("w", encoding="utf-8") as f:
        while True:
            points, offset = client.scroll(
                collection_name=COLLECTION_NAME,
                limit=_BATCH,
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            for p in points:
                f.write(json.dumps(p.payload) + "\n")
                written += 1
            if offset is None:
                break

    return written


def _upsert_batch(
    client: QdrantClient,
    bm25: SparseTextEmbedding,
    points: list[Record],
) -> None:
    if not points:
        return

    texts = [(p.payload or {}).get("text", "") for p in points]
    sparse = list(bm25.embed(texts))

    upserts = [
        PointStruct(
            id=p.id,
            vector={
                "dense": cast("list[float]", p.vector),
                "bm25": SparseVector(
                    indices=sv.indices.tolist(),
                    values=sv.values.tolist(),
                ),
            },
            payload=p.payload,
        )
        for p, sv in zip(points, sparse, strict=True)
    ]

    client.upsert(collection_name=HYBRID_COLLECTION_NAME, points=upserts)


def reindex_hybrid(
    limit: int | None = None,
    must_include_cve_ids: list[str] | None = None,
) -> int:
    """Reuse baseline dense vectors; add BM25 sparse; upsert into cve_hybrid."""
    client = get_client()
    bm25 = SparseTextEmbedding(model_name="Qdrant/bm25")
    seen: set[int] = set()
    total = 0

    if must_include_cve_ids:
        seed_ids = [cve_id_to_point_id(c) for c in must_include_cve_ids]
        seeds = client.retrieve(
            collection_name=COLLECTION_NAME,
            ids=seed_ids,
            with_payload=True,
            with_vectors=True,
        )
        _upsert_batch(client, bm25, seeds)
        seen = {int(p.id) for p in seeds}
        total = len(seeds)

    offset = None

    while limit is None or total < limit:
        points, offset = client.scroll(
            collection_name=COLLECTION_NAME,
            limit=_BATCH,
            offset=offset,
            with_payload=True,
            with_vectors=True,
        )

        batch = [p for p in points if int(p.id) not in seen]

        if limit is not None:
            batch = batch[: limit - total]

        _upsert_batch(client, bm25, batch)
        total += len(batch)

        if offset is None:
            break

    return total
