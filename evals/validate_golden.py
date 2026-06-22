from __future__ import annotations

import json
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue

from threat_intel_rag.config import settings
from threat_intel_rag.ingestion.qdrant_setup import COLLECTION_NAME

QUESTIONS_PATH = Path(__file__).parent / "golden_questions.jsonl"


def cve_exists(client: QdrantClient, cve_id: str) -> bool:
    points, _ = client.scroll(
        collection_name=COLLECTION_NAME,
        scroll_filter=Filter(
            must=[FieldCondition(key="cve_id", match=MatchValue(value=cve_id))]
        ),
        limit=1,
    )
    return len(points) > 0


def main() -> None:
    questions = [
        json.loads(line)
        for line in QUESTIONS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    expected = sorted({cve for q in questions for cve in q["expected_cves"]})
    client = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)
    missing = [cve for cve in expected if not cve_exists(client, cve)]

    print(
        f"Checked {len(expected)} unique expected CVEs "
        f"across {len(questions)} questions"
    )

    if missing:
        print(f"\nMISSING from index ({len(missing)}):")
        for cve in missing:
            print(f"  {cve}")
    else:
        print("All expected CVEs are present in the index.")


if __name__ == "__main__":
    main()
