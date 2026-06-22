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
        answer, retrieved_cves = await run_one(provider, q["question"])

        results.append(
            {
                "id": q["id"],
                "question": q["question"],
                "answer": answer,
                "expected_cves": q["expected_cves"],
                "retrieved_cves": retrieved_cves,
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

    by_difficulty: dict[str, list[float]] = {"easy": [], "medium": [], "hard": []}

    for r in results:
        expected = r["expected_cves"]

        if not expected:
            print(f"  [SKIP] {str(r['id']).capitalize()} No expected CVEs")
            continue

        retrieved = {c.upper() for c in r.get("retrieved_cves", [])}
        found = [cve for cve in expected if cve.upper() in retrieved]
        recall = len(found) / len(expected)
        by_difficulty[r["difficulty"]].append(recall)

        print(
            f"  [{recall:.2f}] {str(r['id']).capitalize()} "
            f"Found {len(found)} / {len(expected)} CVEs: {expected}"
        )

    print()

    for level, recalls in by_difficulty.items():
        if recalls:
            mean_recall = sum(recalls) / len(recalls)
            print(
                f"  [{str(level).capitalize()}] Mean recall of {mean_recall:.2f} "
                f"for {len(recalls)} questions"
            )

    print()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "score":
        score()
    else:
        asyncio.run(main())
