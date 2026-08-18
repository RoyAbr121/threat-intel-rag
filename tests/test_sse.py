import json

from threat_intel_rag.app import _sse


def test_sse_event_is_two_lines() -> None:
    assert _sse("hello") == 'data: "hello"\n\n'


def test_sse_survives_a_newline_token() -> None:
    event = _sse("\n")
    body, terminator = event[: -len("\n\n")], event[-len("\n\n") :]

    # the payload must not contain a bare newline - that would end the event
    assert "\n" not in body
    assert terminator == "\n\n"
    assert json.loads(body.removeprefix("data: ")) == "\n"


def test_sse_round_trips_a_multiline_token() -> None:
    token = "line one\nline two"

    assert json.loads(_sse(token).removeprefix("data: ").strip()) == token
