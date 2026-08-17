from collections.abc import AsyncGenerator

from qdrant_client.models import ScoredPoint

from threat_intel_rag.agent.graph import _grade_chunk, _keeps, _parse_verdicts
from threat_intel_rag.query.rag import resolve_lookup_ids


class _StubProvider:
    """Records the prompts it is given and returns a fixed reply."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    async def generate(self, prompt: str, temperature: float | None = None) -> str:
        self.prompts.append(prompt)

        return self.reply

    async def stream(self, prompt: str) -> AsyncGenerator[str, None]:
        yield self.reply

    async def embed(self, text: str) -> list[float]:
        return [0.0]


def _point(cve_id: str, text: str) -> ScoredPoint:
    return ScoredPoint(
        id=1, version=0, score=1.0, payload={"cve_id": cve_id, "text": text}
    )


def test_keeps_plain_verdicts() -> None:
    assert _keeps("keep") is True
    assert _keeps("drop") is False


def test_keeps_ignores_case_and_whitespace() -> None:
    assert _keeps("  DROP\n") is False


def test_keeps_handles_markdown_emphasis() -> None:
    assert _keeps("**drop**") is False


def test_keeps_on_ambiguous_answer() -> None:
    assert _keeps("keep - do not drop this record") is True


def test_keeps_on_unparseable_answer() -> None:
    assert _keeps("I cannot determine this.") is True


def test_parse_verdicts_reads_lines() -> None:
    raw = "CVE-2021-22893: keep\nCVE-2021-22894: drop"

    assert _parse_verdicts(raw) == {
        "CVE-2021-22893": True,
        "CVE-2021-22894": False,
    }


def test_parse_verdicts_tolerates_decoration() -> None:
    raw = "- CVE-2019-11539 - drop  // requires a valid session\n"

    assert _parse_verdicts(raw) == {"CVE-2019-11539": False}


def test_parse_verdicts_empty_when_nothing_parses() -> None:
    # an empty map means every record defaults to keep - fail-open
    assert _parse_verdicts("I cannot determine this.") == {}


async def test_grade_chunk_returns_a_verdict_per_record() -> None:
    provider = _StubProvider("CVE-2021-22893: keep\nCVE-2021-22894: drop")
    hits = [
        _point("CVE-2021-22893", "unauthenticated remote file read"),
        _point("CVE-2021-22894", "an authenticated attacker can ..."),
    ]

    verdicts = await _grade_chunk("pre-auth Pulse?", hits, provider)

    assert verdicts == {"CVE-2021-22893": True, "CVE-2021-22894": False}
    assert "unauthenticated remote file read" in provider.prompts[0]


def test_resolve_dedupes_literal_and_alias_ids() -> None:
    ids = resolve_lookup_ids("Is CVE-2020-0796 the same as SMBGhost?")

    assert ids == ["CVE-2020-0796"]


def test_resolve_empty_for_product_questions() -> None:
    assert resolve_lookup_ids("What RCE vulnerabilities affect Apache Struts?") == []
