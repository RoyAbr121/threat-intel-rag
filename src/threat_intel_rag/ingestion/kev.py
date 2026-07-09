from __future__ import annotations

import httpx
from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue

from threat_intel_rag.ingestion.qdrant_setup import HYBRID_COLLECTION_NAME, get_client

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_BATCH = 512


async def fetch_kev_ids() -> list[str]:
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(KEV_URL)
        response.raise_for_status()

    return [v["cveID"] for v in response.json()["vulnerabilities"]]


def stamp_known_exploited(cve_ids: list[str]) -> int:
    """Overlay known_exploited=true onto matching cve_hybrid records.

    Filter-based selection: KEV entries absent from the corpus are a no-op.
    Re-ingestion replaces payloads wholesale, so this must re-run after any
    reindex (see NOTES.md).
    """
    client = get_client()

    for i in range(0, len(cve_ids), _BATCH):
        batch = cve_ids[i : i + _BATCH]
        client.set_payload(
            collection_name=HYBRID_COLLECTION_NAME,
            payload={"known_exploited": True},
            points=Filter(
                must=[FieldCondition(key="cve_id", match=MatchAny(any=batch))]
            ),
        )

    return client.count(
        collection_name=HYBRID_COLLECTION_NAME,
        count_filter=Filter(
            must=[FieldCondition(key="known_exploited", match=MatchValue(value=True))]
        ),
        exact=True,
    ).count
