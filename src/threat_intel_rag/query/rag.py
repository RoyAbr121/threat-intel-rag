from __future__ import annotations

from collections.abc import AsyncGenerator

from qdrant_client import QdrantClient

from threat_intel_rag.config import settings
from threat_intel_rag.ingestion.qdrant_setup import COLLECTION_NAME
from threat_intel_rag.llm.protocol import LLMProvider

_PROMPT_TEMPLATE = """\
You are a cybersecurity analyst assistant. Answer the question below using \
only the context provided. If the context does not contain enough information, \
say so. Cite the CVE IDs that support your answer.

Context:
{context}

Question: {question}        

Answer:"""


async def rag_stream(
    question: str,
    provider: LLMProvider,
    top_k: int = 5,
) -> AsyncGenerator[str, None]:
    vector = await provider.embed(question)
    qdrant = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)

    hits = qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=top_k,
    ).points

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
