from __future__ import annotations

from collections.abc import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from threat_intel_rag.llm.ollama import OllamaProvider
from threat_intel_rag.query.rag import rag_stream

logger = structlog.get_logger()

app = FastAPI(title="Threat Intel RAG", version="0.1.0")


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/ready")
async def ready() -> JSONResponse:
    return JSONResponse({"status": "ready"})


@app.get("/live")
async def live() -> JSONResponse:
    return JSONResponse({"status": "live"})


class QueryRequest(BaseModel):
    question: str
    top_k: int = Field(default=5, ge=1, le=20)


@app.post("/v1/query")
async def query(request: QueryRequest) -> StreamingResponse:
    provider = OllamaProvider()

    async def event_stream() -> AsyncGenerator[str, None]:
        async for token in rag_stream(request.question, provider, request.top_k):
            yield f"data: {token}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
