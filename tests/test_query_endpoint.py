"""End-to-end check of POST /v1/query, through HTTP and the SSE wire format.

The eval harness calls the graph in-process, so it never sees this endpoint.
Two real defects hid here for exactly that reason: the endpoint serving the
Phase 2 naive-dense path (found in 4.1), and SSE framing dropping newlines
(found in 4.2a). This test sends a real HTTP request to the real app, with
its real compiled graph, and stubs only the two external services at their
edges - the Qdrant lookup and Ollama - so it runs in CI with no services.
"""

import json
import re
from collections.abc import AsyncGenerator

import pytest
from fastapi.testclient import TestClient
from qdrant_client.models import ScoredPoint

import threat_intel_rag.agent.graph as graph_module
import threat_intel_rag.app as app_module

_PINNED = "CVE-2016-5195"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


async def _fake_lookup(cve_ids: list[str], top_k: int = 5) -> list[ScoredPoint]:
    return [
        ScoredPoint(
            id=1,
            version=0,
            score=1.0,
            payload={"cve_id": cve, "text": f"{cve} race condition in mm/gup.c"},
        )
        for cve in cve_ids
    ]


async def _fake_stream(prompt: str) -> AsyncGenerator[str, None]:
    # cite only what the context actually contains, so the pinned ID can
    # reach the client only if the routed lookup put it there
    cited = sorted(set(_CVE_RE.findall(prompt.split("Question:")[0])))

    yield "Dirty COW is a race condition"
    yield ".\n\n"  # the multi-line token that 4.2a's framing bug swallowed
    yield f"[{', '.join(cited)}]"


async def _must_not_run(*args: object, **kwargs: object) -> list[ScoredPoint]:
    raise AssertionError("a question with a literal CVE ID must take the routed path")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(graph_module, "exact_id_retrieve", _fake_lookup)
    monkeypatch.setattr(graph_module, "rewrite_retrieve", _must_not_run)
    # the app's graph captured this provider instance when it was built at
    # import time, so patching the instance reaches the served graph
    monkeypatch.setattr(app_module.provider, "stream", _fake_stream)
    monkeypatch.setattr(app_module.provider, "embed", _must_not_run)
    monkeypatch.setattr(app_module.provider, "generate", _must_not_run)

    return TestClient(app_module.app)


def _events(body: str) -> list[str]:
    assert body.endswith("\n\n"), "every event must end with a blank line"

    return body[: -len("\n\n")].split("\n\n")


def test_query_streams_well_formed_sse(client: TestClient) -> None:
    response = client.post("/v1/query", json={"question": f"What is {_PINNED}?"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")

    events = _events(response.text)

    # the sentinel is framing, not payload, so it stays unencoded
    assert events[-1] == "data: [DONE]"

    for event in events[:-1]:
        assert event.startswith("data: ")
        assert "\n" not in event, "a bare newline inside an event ends it early"
        assert isinstance(json.loads(event.removeprefix("data: ")), str)


def test_routed_question_returns_its_pinned_cve(client: TestClient) -> None:
    response = client.post("/v1/query", json={"question": f"What is {_PINNED}?"})

    events = _events(response.text)
    answer = "".join(json.loads(e.removeprefix("data: ")) for e in events[:-1])

    assert f"[{_PINNED}]" in answer
    assert ".\n\n" in answer, "the paragraph-break token must survive the wire"
