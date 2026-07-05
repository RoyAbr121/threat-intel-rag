from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator
from functools import lru_cache

from fastembed import SparseTextEmbedding
from fastembed.rerank.cross_encoder import TextCrossEncoder
from qdrant_client.models import (
    FieldCondition,
    Filter,
    Fusion,
    FusionQuery,
    MatchAny,
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

_REWRITE_TEMPLATE = """\
You rewrite cybersecurity questions into search queries for a CVE/NVD index.
Expand any vulnerability codename (e.g. "Log4Shell", "Heartbleed") into the \
affected product, the vulnerability type, and the CVE identifier if you know it. \
Keep it terse - keywords, not prose. Output only the rewritten query, nothing else.

Question: {question}
Rewritten query:"""

_CODENAME_ALIASES: dict[str, list[str]] = {
    "log4shell": ["CVE-2021-44228"],
    "dirty cow": ["CVE-2016-5195"],
    "dirty pipe": ["CVE-2022-0847"],
    "printnightmare": ["CVE-2021-34527"],
    "zerologon": ["CVE-2020-1472"],
    "pwnkit": ["CVE-2021-4034"],
    "spring4shell": ["CVE-2022-22965"],
    "heartbleed": ["CVE-2014-0160"],
    "shellshock": ["CVE-2014-6271"],
    "poodle": ["CVE-2014-3566"],
    "eternalblue": ["CVE-2017-0144"],
    "bluekeep": ["CVE-2019-0708"],
    "meltdown": ["CVE-2017-5754"],
    "spectre": ["CVE-2017-5753", "CVE-2017-5715"],
    "follina": ["CVE-2022-30190"],
    "baron samedit": ["CVE-2021-3156"],
    "ghostcat": ["CVE-2020-1938"],
    "proxylogon": ["CVE-2021-26855", "CVE-2021-27065"],
    "smbghost": ["CVE-2020-0796"],
    "sigred": ["CVE-2020-1350"],
}


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


async def rewrite_query(question: str, provider: LLMProvider) -> str:
    prompt = _REWRITE_TEMPLATE.format(question=question)
    rewritten = await provider.generate(prompt, temperature=0.0)

    return rewritten.strip().strip('"').strip()


async def rewrite_retrieve(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> list[ScoredPoint]:
    expansion = await rewrite_query(question, provider)
    augmented = f"{question} {expansion}"

    return await rerank_retrieve(augmented, provider, top_k=top_k)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_cve_ids(text: str) -> list[str]:
    seen: list[str] = []

    for match in _CVE_RE.findall(text):
        cve = match.upper()

        if cve not in seen:
            seen.append(cve)

    return seen


async def exact_id_retrieve(cve_ids: list[str], top_k: int = 5) -> list[ScoredPoint]:
    qdrant = get_client()
    records, _ = qdrant.scroll(
        collection_name=HYBRID_COLLECTION_NAME,
        scroll_filter=Filter(
            must=[FieldCondition(key="cve_id", match=MatchAny(any=cve_ids))]
        ),
        limit=top_k,
        with_payload=True,
    )

    return [
        ScoredPoint(id=r.id, version=0, score=1.0, payload=r.payload) for r in records
    ]


def _extract_alias_ids(text: str) -> list[str]:
    lowered = text.lower()
    ids: list[str] = []

    for alias, cves in _CODENAME_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lowered):
            ids.extend(cve for cve in cves if cve not in ids)

    return ids


async def route_retrieve(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> list[ScoredPoint]:
    cve_ids = _extract_cve_ids(question)
    cve_ids += [c for c in _extract_alias_ids(question) if c not in cve_ids]

    if cve_ids:
        hits = await exact_id_retrieve(cve_ids, top_k=top_k)

        if hits:
            return hits

    return await rewrite_retrieve(question, provider, top_k=top_k)
