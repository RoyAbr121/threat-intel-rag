import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

logger = structlog.get_logger()

app = FastAPI(title="Threat Intel RAG", version="0.1.0")


@app.get("/health")  # type: ignore[misc]
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/ready")  # type: ignore[misc]
async def ready() -> JSONResponse:
    return JSONResponse({"status": "ready"})


@app.get("/live")  # type: ignore[misc]
async def live() -> JSONResponse:
    return JSONResponse({"status": "live"})
