from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

import httpx
from qdrant_client import QdrantClient
from qdrant_client.models import ScoredPoint

from threat_intel_rag.config import settings
from threat_intel_rag.ingestion.pipeline import ingest_cves
from threat_intel_rag.ingestion.qdrant_setup import COLLECTION_NAME


async def embed_query(text: str) -> list[float]:
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{settings.ollama_base_url}/api/embeddings",
            json={"model": settings.ollama_embed_model, "prompt": text},
        )

        response.raise_for_status()

        return list(response.json()["embedding"])


def search(query: str, top_k: int = 5) -> list[ScoredPoint]:
    vector = asyncio.run(embed_query(query))
    client = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)

    return client.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=top_k,
    ).points


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Intel RAG CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Run CVE ingestion")
    ingest_parser.add_argument("--limit", type=int, default=None)

    ingest_parser.add_argument(
        "--start-date",
        type=lambda s: datetime.fromisoformat(s),
        default=None,
        help="Ingest only CVEs published on or after this date (YYYY-MM-DD)",
    )

    search_parser = subparsers.add_parser("search", help="Search CVE index")
    search_parser.add_argument("query", type=str)
    search_parser.add_argument("--top-k", type=int, default=5)

    args = parser.parse_args()

    if args.command == "ingest":
        asyncio.run(ingest_cves(limit=args.limit, start_date=args.start_date))
        print("Ingestion complete.")

    elif args.command == "search":
        results = search(args.query, top_k=args.top_k)

        for hit in results:
            payload = hit.payload or {}
            print(f"\n[{payload.get('cve_id')}] score={hit.score:.4f}")
            print(payload.get("text", "")[:200])


if __name__ == "__main__":
    main()
