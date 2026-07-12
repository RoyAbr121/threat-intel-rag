from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from qdrant_client.models import ScoredPoint

from threat_intel_rag.llm.ollama import OllamaProvider
from threat_intel_rag.query.rag import hybrid_retrieve, rerank_retrieve, rewrite_query

QUESTIONS = Path(__file__).parent / "golden_questions.jsonl"
POOL = 50  # deliberately deeper than production candidates=20 so ranks stay observable


# The 3.5 residual failure set: every zero/partial question, all category=product
# (q42/q43 are product comparisons). Override via argv, e.g. `... q24 q26`.
FAILING = ["q21", "q22", "q23", "q24", "q25", "q26", "q27", "q30", "q31", "q42", "q43"]


def _ranks(hits: list[ScoredPoint]) -> dict[str, int]:
    return {(h.payload or {}).get("cve_id", ""): i for i, h in enumerate(hits)}


def _fmt(rank: int | None) -> str:
    return "ABSENT" if rank is None else f"rank {rank:2d}"


async def diagnose(q: dict[str, str], provider: OllamaProvider) -> None:
    question = q["question"]
    expansion = await rewrite_query(question, provider)
    augmented = f"{question} {expansion}"

    raw_pool = await hybrid_retrieve(question, provider, top_k=POOL)
    aug_pool = await hybrid_retrieve(augmented, provider, top_k=POOL)
    reranked = await rerank_retrieve(augmented, provider, top_k=POOL, candidates=POOL)

    raw, aug, post = _ranks(raw_pool), _ranks(aug_pool), _ranks(reranked)
    top5 = ", ".join((h.payload or {}).get("cve_id", "?") for h in reranked[:5])

    print(f"\n{q['id']} [{q['difficulty']}] {question}")
    print(f"  expansion: {expansion}")
    print(f"  post-rerank top-5: {top5}")

    for cve in q["expected_cves"]:
        print(
            f"  {cve}: raw-pool {_fmt(raw.get(cve))}"
            f" | aug-pool {_fmt(aug.get(cve))}"
            f" | post-rerank {_fmt(post.get(cve))}"
        )


async def main() -> None:
    wanted = set(sys.argv[1:]) or set(FAILING)
    provider = OllamaProvider()
    questions = [
        json.loads(line)
        for line in QUESTIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    for q in questions:
        if q["id"] in wanted and q["expected_cves"]:
            await diagnose(q, provider)


if __name__ == "__main__":
    asyncio.run(main())
