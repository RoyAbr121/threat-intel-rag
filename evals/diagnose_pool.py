from __future__ import annotations

import asyncio
import json
from pathlib import Path

from threat_intel_rag.llm.ollama import OllamaProvider
from threat_intel_rag.query.rag import hybrid_retrieve

QUESTIONS = Path(__file__).parent / "golden_questions.jsonl"


async def main() -> None:
    provider = OllamaProvider()
    questions = [
        json.loads(line)
        for line in QUESTIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    for q in questions:
        expected = q["expected_cves"]

        if not expected:
            continue

        hits = await hybrid_retrieve(q["question"], provider, top_k=50)
        ranks = {(h.payload or {}).get("cve_id", ""): i for i, h in enumerate(hits)}

        for cve in expected:
            rank = ranks.get(cve)

            if rank is None:
                verdict = "ABSENT (>50 — recall problem → 3.3)"
            elif rank < 5:
                verdict = f"top-5 (rank {rank})"
            else:
                verdict = f"in-pool rank {rank} (rerank can fix → 3.2)"

            print(f"  [{q['difficulty']:6}] {q['id']} {cve}: {verdict}")


if __name__ == "__main__":
    asyncio.run(main())
