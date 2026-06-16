from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    async def generate(self, prompt: str) -> str: ...

    def stream(self, prompt: str) -> AsyncGenerator[str, None]: ...

    async def embed(self, text: str) -> list[float]: ...
