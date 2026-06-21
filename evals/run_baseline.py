from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from threat_intel_rag.llm.ollama import OllamaProvider
from threat_intel_rag.query.rag import retrieve, stream_answer

EVALS_DIR = Path(__file__).parent
QUESTIONS_PATH = EVALS_DIR / "golden_questions.jsonl"
RESULTS_PATH = EVALS_DIR / "baseline_results.jsonl"


async def run_one(provider: OllamaProvider, question: str) -> tuple[str, list[str]]:
    hits = await retrieve(question, provider, top_k=5)
    retrieved_cves = [(hit.payload or {}).get("cve_id", "") for hit in hits]

    tokens: list[str] = []

    async for token in stream_answer(question, hits, provider):
        tokens.append(token)
        print(token, end="", flush=True)

    print()
    return "".join(tokens), retrieved_cves


async def main() -> None:
    provider = OllamaProvider()
    questions = [
        json.loads(line)
        for line in QUESTIONS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    results = []

    for q in questions:
        q_str = f"[{q['id']}] ({q['difficulty']}) {q['question']}"
        q_line = f"{'=' * len(q_str)}"
        print(f"\n{q_line}\n{q_str}\n{q_line}")
        answer = await run_one(provider, q["question"])

        results.append(
            {
                "id": q["id"],
                "question": q["question"],
                "answer": answer,
                "expected_cves": q["expected_cves"],
                "category": q["category"],
                "difficulty": q["difficulty"],
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    RESULTS_PATH.write_text("\n".join(json.dumps(r) for r in results), encoding="utf-8")

    print(f"\nResults saved to {RESULTS_PATH}")


def score() -> None:
    results = [
        json.loads(line)
        for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    by_difficulty: dict[str, list[bool]] = {"easy": [], "medium": [], "hard": []}

    for r in results:
        expected = r["expected_cves"]

        if not expected:
            continue

        retrieved = [c.upper() for c in r.get("retrieved_cves", [])]
        hit = all(cve.upper() in retrieved for cve in expected)
        by_difficulty[r["difficulty"]].append(hit)
        status = "HIT" if hit else "MISS"
        print(f"  [{status}] {r['id']} — expected: {expected}")

    print()

    for level, hits in by_difficulty.items():
        if hits:
            rate = sum(hits) / len(hits) * 100
            print(f"  {level:6s}: {sum(hits)}/{len(hits)} = {rate:.0f}%")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "score":
        score()
    else:
        asyncio.run(main())
