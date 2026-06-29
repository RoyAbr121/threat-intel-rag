from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from functools import lru_cache

from fastembed import SparseTextEmbedding
from fastembed.rerank.cross_encoder import TextCrossEncoder
from qdrant_client.models import (
    Fusion,
    FusionQuery,
    Prefetch,
    ScoredPoint,
    SparseVector,
)

from threat_intel_rag.ingestion.qdrant_setup import (
    COLLECTION_NAME,
    HYBRID_COLLECTION_NAME,
    get_client,
)
from threat_intel_rag.llm.protocol import LLMProvider

_PROMPT_TEMPLATE = """\
You are a cybersecurity analyst assistant. Answer the question below using \
only the context provided. If the context does not contain enough information, \
say so. Cite the CVE IDs that support your answer.

Context:
{context}

Question: {question}        

Answer:"""


async def retrieve(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> list[ScoredPoint]:
    vector = await provider.embed(question)
    qdrant = get_client()

    return qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=top_k,
    ).points


async def stream_answer(
    question: str,
    hits: list[ScoredPoint],
    provider: LLMProvider,
) -> AsyncGenerator[str, None]:
    context_parts = []

    for hit in hits:
        payload = hit.payload or {}
        cve_id = payload.get("cve_id", "unknown")
        text = payload.get("text", "")
        context_parts.append(f"[{cve_id}] {text}")

    context = "\n\n".join(context_parts)
    prompt = _PROMPT_TEMPLATE.format(context=context, question=question)

    async for token in provider.stream(prompt):
        yield token


async def rag_stream(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> AsyncGenerator[str, None]:
    hits = await retrieve(question, provider, top_k)

    async for token in stream_answer(question, hits, provider):
        yield token


@lru_cache(maxsize=1)
def _bm25() -> SparseTextEmbedding:
    return SparseTextEmbedding(model_name="Qdrant/bm25")


async def hybrid_retrieve(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> list[ScoredPoint]:
    dense = await provider.embed(question)
    sparse = next(iter(_bm25().query_embed(question)))
    qdrant = get_client()

    return qdrant.query_points(
        collection_name=HYBRID_COLLECTION_NAME,
        prefetch=[
            Prefetch(query=dense, using="dense", limit=top_k * 4),
            Prefetch(
                query=SparseVector(
                    indices=sparse.indices.tolist(),
                    values=sparse.values.tolist(),
                ),
                using="bm25",
                limit=top_k * 4,
            ),
        ],
        query=FusionQuery(fusion=Fusion.RRF),
        limit=top_k,
    ).points


@lru_cache(maxsize=1)
def _reranker() -> TextCrossEncoder:
    return TextCrossEncoder(model_name="Xenova/ms-marco-MiniLM-L-6-v2")


async def rerank_retrieve(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
    candidates: int = 50,
) -> list[ScoredPoint]:
    pool = await hybrid_retrieve(question, provider, top_k=candidates)

    if not pool:
        return []

    docs = [(p.payload or {}).get("text", "") for p in pool]
    scores = await asyncio.to_thread(lambda: list(_reranker().rerank(question, docs)))

    for point, score in zip(pool, scores, strict=True):
        point.score = score

    pool.sort(key=lambda p: p.score, reverse=True)

    return pool[:top_k]
