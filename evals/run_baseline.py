from __future__ import annotations

import asyncio
import json
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph.graph.state import CompiledStateGraph
from qdrant_client.models import ScoredPoint

from threat_intel_rag.agent.graph import AgentState, build_graph
from threat_intel_rag.llm.ollama import OllamaProvider
from threat_intel_rag.query.rag import (
    hybrid_retrieve,
    rerank_retrieve,
    retrieve,
    rewrite_retrieve,
    route_retrieve,
    stream_answer,
)

EVALS_DIR = Path(__file__).parent
QUESTIONS_PATH = EVALS_DIR / "golden_questions.jsonl"
RESULTS_PATH = EVALS_DIR / "baseline_results.jsonl"
HYBRID_RESULTS_PATH = EVALS_DIR / "hybrid_results.jsonl"
RERANK_RESULTS_PATH = EVALS_DIR / "rerank_results.jsonl"
REWRITE_RESULTS_PATH = EVALS_DIR / "rewrite_results.jsonl"
ROUTE_RESULTS_PATH = EVALS_DIR / "route_results.jsonl"
AGENT_RESULTS_PATH = EVALS_DIR / "agent_results.jsonl"

Retriever = Callable[[str, OllamaProvider, int], Awaitable[list[ScoredPoint]]]


async def run_one(
    provider: OllamaProvider,
    question: str,
    retriever: Retriever,
) -> tuple[str, list[str], float, float]:
    start = time.perf_counter()
    hits = await retriever(question, provider, 5)
    retrieval_ms = (time.perf_counter() - start) * 1000
    retrieved_cves = [(hit.payload or {}).get("cve_id", "") for hit in hits]

    tokens: list[str] = []

    async for token in stream_answer(question, hits, provider):
        tokens.append(token)
        print(token, end="", flush=True)

    total_ms = (time.perf_counter() - start) * 1000
    print()
    return "".join(tokens), retrieved_cves, retrieval_ms, total_ms


async def run_one_agent(
    graph: CompiledStateGraph[AgentState], question: str
) -> tuple[str, list[str], float, float]:
    start = time.perf_counter()
    retrieval_ms = 0.0
    retrieved_cves: list[str] = []
    tokens: list[str] = []

    stream = graph.astream(
        {"question": question, "top_k": 5}, stream_mode=["updates", "custom"]
    )

    async for mode, chunk in stream:
        if mode == "custom":
            tokens.append(chunk)
            print(chunk, end="", flush=True)
        elif isinstance(chunk, dict):
            if "retrieve" in chunk:
                retrieval_ms = (time.perf_counter() - start) * 1000

            # grade overwrites retrieve: score what generate will actually see
            node_update = chunk.get("grade") or chunk.get("retrieve")

            if node_update and "hits" in node_update:
                hits = node_update["hits"]
                retrieved_cves = [(h.payload or {}).get("cve_id", "") for h in hits]

    total_ms = (time.perf_counter() - start) * 1000
    print()
    return "".join(tokens), retrieved_cves, retrieval_ms, total_ms


async def main(
    provider: OllamaProvider,
    retriever: Retriever | None,
    graph: CompiledStateGraph[AgentState] | None,
    questions_path: Path,
    results_path: Path,
) -> None:
    questions = [
        json.loads(line)
        for line in questions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    results = []

    for q in questions:
        q_str = f"[{q['id']}] ({q['difficulty']}) {q['question']}"
        q_line = f"{'=' * len(q_str)}"
        print(f"\n{q_line}\n{q_str}\n{q_line}")

        if graph is not None:
            answer, retrieved_cves, retrieval_ms, total_ms = await run_one_agent(
                graph, q["question"]
            )
        else:
            assert retriever is not None
            answer, retrieved_cves, retrieval_ms, total_ms = await run_one(
                provider, q["question"], retriever
            )

        results.append(
            {
                "id": q["id"],
                "question": q["question"],
                "answer": answer,
                "expected_cves": q["expected_cves"],
                "retrieved_cves": retrieved_cves,
                "category": q["category"],
                "difficulty": q["difficulty"],
                "retrieval_ms": round(retrieval_ms, 1),
                "total_ms": round(total_ms, 1),
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    results_path.write_text("\n".join(json.dumps(r) for r in results), encoding="utf-8")
    print(f"\nResults saved to {results_path}")


def score(results_path: Path) -> None:
    results = [
        json.loads(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
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
    _latency_summary(results)


def _pctl(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[round(p * (len(ordered) - 1))]


def _latency_summary(results: list[dict[str, Any]]) -> None:
    timed = [r for r in results if "retrieval_ms" in r]

    if not timed:
        return

    retrieval = [r["retrieval_ms"] for r in timed]
    total = [r["total_ms"] for r in timed]

    print(
        f"  [Latency] retrieval p50 {_pctl(retrieval, 0.50):,.0f} ms / "
        f"p95 {_pctl(retrieval, 0.95):,.0f} ms | "
        f"end-to-end p50 {_pctl(total, 0.50):,.0f} ms / "
        f"p95 {_pctl(total, 0.95):,.0f} ms "
        f"({len(timed)} questions)"
    )
    print()


if __name__ == "__main__":
    args = sys.argv[1:]
    retriever: Retriever | None

    if "agent" in args:
        retriever, mode = None, "agent"
    elif "route" in args:
        retriever, mode = route_retrieve, "route"
    elif "rewrite" in args:
        retriever, mode = rewrite_retrieve, "rewrite"
    elif "rerank" in args:
        retriever, mode = rerank_retrieve, "rerank"
    elif "hybrid" in args:
        retriever, mode = hybrid_retrieve, "hybrid"
    else:
        retriever, mode = retrieve, "baseline"

    version = "v1" if "v1" in args else "v2"
    questions_path = EVALS_DIR / f"{version}_golden_questions.jsonl"
    results_path = EVALS_DIR / f"{version}_{mode}_results.jsonl"

    if "score" in args:
        score(results_path)
    else:
        provider = OllamaProvider()
        graph = build_graph(provider) if retriever is None else None
        asyncio.run(main(provider, retriever, graph, questions_path, results_path))
