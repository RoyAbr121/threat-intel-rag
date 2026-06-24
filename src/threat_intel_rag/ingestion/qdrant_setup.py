from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    Modifier,
    PayloadSchemaType,
    SparseVectorParams,
    VectorParams,
)

from threat_intel_rag.config import settings

COLLECTION_NAME = "cve_vectors"
HYBRID_COLLECTION_NAME = "cve_hybrid"
VECTOR_SIZE = 768


def ensure_collection() -> None:
    client = get_client()
    existing = {c.name for c in client.get_collections().collections}

    if COLLECTION_NAME in existing:
        return

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )

    client.create_payload_index(
        collection_name=COLLECTION_NAME,
        field_name="source",
        field_schema=PayloadSchemaType.KEYWORD,
    )

    client.create_payload_index(
        collection_name=COLLECTION_NAME,
        field_name="embed_model",
        field_schema=PayloadSchemaType.KEYWORD,
    )


def ensure_hybrid_collection() -> None:
    client = get_client()

    existing = {c.name for c in client.get_collections().collections}
    if HYBRID_COLLECTION_NAME in existing:
        return

    client.create_collection(
        collection_name=HYBRID_COLLECTION_NAME,
        vectors_config={
            "dense": VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        },
        sparse_vectors_config={
            "bm25": SparseVectorParams(modifier=Modifier.IDF),
        },
    )

    for field in ("source", "embed_model", "cve_id"):
        client.create_payload_index(
            collection_name=HYBRID_COLLECTION_NAME,
            field_name=field,
            field_schema=PayloadSchemaType.KEYWORD,
        )


def get_client() -> QdrantClient:
    return QdrantClient(
        host=settings.qdrant_host,
        port=settings.qdrant_port,
        check_compatibility=False,
    )
