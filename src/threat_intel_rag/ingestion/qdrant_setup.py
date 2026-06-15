from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PayloadSchemaType, VectorParams

from threat_intel_rag.config import settings

COLLECTION_NAME = "cve_vectors"
VECTOR_SIZE = 768


def ensure_collection() -> None:
    client = QdrantClient(
        host=settings.qdrant_host,
        port=settings.qdrant_port,
    )

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
