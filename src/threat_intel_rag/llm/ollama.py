from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any

import httpx

from threat_intel_rag.config import settings


class OllamaProvider:
    def __init__(self) -> None:
        self._base_url = settings.ollama_base_url
        self._model = settings.ollama_llm_model
        self._embed_model = settings.ollama_embed_model

    async def generate(self, prompt: str, temperature: float | None = None) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        if temperature is not None:
            payload["options"] = {"temperature": temperature}
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(f"{self._base_url}/api/generate", json=payload)
            response.raise_for_status()

            return str(response.json()["response"])

    async def stream(self, prompt: str) -> AsyncGenerator[str, None]:
        async with (
            httpx.AsyncClient(timeout=120.0) as client,
            client.stream(
                "POST",
                f"{self._base_url}/api/generate",
                json={"model": self._model, "prompt": prompt, "stream": True},
            ) as response,
        ):
            response.raise_for_status()

            async for line in response.aiter_lines():
                if not line:
                    continue
                chunk = json.loads(line)
                if not chunk.get("done"):
                    yield chunk["response"]

    async def embed(self, text: str) -> list[float]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self._base_url}/api/embeddings",
                json={"model": self._embed_model, "prompt": text},
            )
            response.raise_for_status()
            return list(response.json()["embedding"])
