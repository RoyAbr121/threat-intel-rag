from __future__ import annotations

import re
from collections import defaultdict

from qdrant_client.models import FieldCondition, Filter, MatchAny

from threat_intel_rag.ingestion.qdrant_setup import HYBRID_COLLECTION_NAME, get_client

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
