import asyncio
import re
from typing import TypedDict

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from qdrant_client.models import ScoredPoint

from threat_intel_rag.llm.protocol import LLMProvider
from threat_intel_rag.query.rag import (
    exact_id_retrieve,
    resolve_lookup_ids,
    rewrite_retrieve,
    stream_answer,
)

# contrast is load-bearing: the grader discriminates at 5 records, keeps
# everything at 10 (dilution) and at 1 (nothing to compare against)
_GRADE_BATCH = 5

# retry widens the final cut, not the search depth: 3.8 showed extra depth
# only admits more same-product crowd, while q30's missing record sits at
# rank 6 - one place outside top_k
_RETRY_HEADROOM = 5
_MAX_ATTEMPTS = 2

_GRADE_TEMPLATE = """\
You are checking search results against a question's stated conditions.

Question: {question}

Records:
{records}

These phrases mean the same thing:
- "pre-authentication", "pre-auth", "unauthenticated", "without \
authentication", "no credentials required", "remote unauthenticated" - the \
attacker needs no valid account.
- "authenticated", "post-authentication", "authenticated attacker", \
"requires a valid session" - the attacker needs a valid account.
- "remote code execution", "RCE", "arbitrary code execution", "execute \
arbitrary commands" - the same class of impact.

For each record above, decide whether its own text satisfies EVERY condition \
the question states - such as authentication requirements, a year, a \
vulnerability type, or a specific product. Judge only from the record text; \
do not use outside knowledge. Answer "keep" if the record satisfies every \
condition, and "drop" if it does not.

Output one line per record and nothing else, in exactly this format:
CVE-0000-0000: keep
CVE-0000-0000: drop

Include all {count} records.
"""


class AgentState(TypedDict, total=False):
    question: str
    top_k: int
    hits: list[ScoredPoint]
    answer: str
    routed: bool

    attempts: int


# local to grading: unlike rag.py's ID regex, this one also captures the
# verdict that follows the ID on the same line
_CVE_LINE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s*:?\s*(.*)", re.IGNORECASE)


def _cve_of(hit: ScoredPoint) -> str:
    return str((hit.payload or {}).get("cve_id", "")).upper()


def _parse_verdicts(raw: str) -> dict[str, bool]:
    verdicts: dict[str, bool] = {}

    for line in raw.splitlines():
        match = _CVE_LINE_RE.search(line)

        if match:
            verdicts[match.group(1).upper()] = _keeps(match.group(2))

    return verdicts


def _keeps(raw: str) -> bool:
    head = raw.strip().lower()[:20]

    # fail-open: only an unambiguous "drop" removes a record, so a hedged
    # or unparseable answer keeps it
    return "keep" in head or "drop" not in head


async def _grade_chunk(
    question: str, hits: list[ScoredPoint], provider: LLMProvider
) -> dict[str, bool]:
    records = "\n\n".join(
        f"[{(h.payload or {}).get('cve_id', 'unknown')}] "
        f"{(h.payload or {}).get('text', '')}"
        for h in hits
    )

    prompt = _GRADE_TEMPLATE.format(question=question, records=records, count=len(hits))
    raw = await provider.generate(prompt, temperature=0.0)
    # print(f"\n--- CHUNK ({len(hits)}) ---\n{raw.strip()}\n")

    return _parse_verdicts(raw)


def build_graph(provider: LLMProvider) -> CompiledStateGraph[AgentState]:
    async def retrieve_node(state: AgentState) -> AgentState:
        top_k = state.get("top_k", 5)
        attempts = state.get("attempts", 0)

        if attempts == 0:
            ids = resolve_lookup_ids(state["question"])

            if ids:
                hits = await exact_id_retrieve(ids, top_k=top_k)

                if hits:
                    return {"hits": hits, "routed": True, "attempts": attempts + 1}

            hits = await rewrite_retrieve(state["question"], provider, top_k=top_k)

        else:
            # the retry: same cascade, same depth, wider final cut
            hits = await rewrite_retrieve(
                state["question"], provider, top_k=top_k + _RETRY_HEADROOM
            )

        return {"hits": hits, "routed": False, "attempts": attempts + 1}

    async def grade_node(state: AgentState) -> AgentState:
        hits = state["hits"]
        top_k = state.get("top_k", 5)
        chunks = [hits[i : i + _GRADE_BATCH] for i in range(0, len(hits), _GRADE_BATCH)]
        graded = await asyncio.gather(
            *(_grade_chunk(state["question"], chunk, provider) for chunk in chunks)
        )
        verdicts: dict[str, bool] = {}

        for chunk_verdicts in graded:
            verdicts.update(chunk_verdicts)

        # a CVE the grader never mentioned defaults to keep
        survivors = [h for h in hits if verdicts.get(_cve_of(h), True)]

        if not survivors:
            survivors = hits  # fail-open: rejecting everything is a grader error

        # always cap at top_k so the eval stays an honest top-5 metric,
        # even when the wide retry handed us 10 candidates
        return {"hits": survivors[:top_k]}

    async def generate_node(state: AgentState) -> AgentState:
        writer = get_stream_writer()
        tokens: list[str] = []

        async for token in stream_answer(state["question"], state["hits"], provider):
            writer(token)
            tokens.append(token)

        return {"answer": "".join(tokens)}

    def after_retrieve(state: AgentState) -> str:
        return "generate" if state.get("routed") else "grade"

    def after_grade(state: AgentState) -> str:
        enough = len(state.get("hits", [])) >= state.get("top_k", 5)
        spent = state.get("attempts", 0) >= _MAX_ATTEMPTS

        return "generate" if enough or spent else "retrieve"

    builder = StateGraph(AgentState)
    builder.add_node("retrieve", retrieve_node)
    builder.add_node("generate", generate_node)
    builder.add_node("grade", grade_node)
    builder.add_edge(START, "retrieve")

    builder.add_conditional_edges(
        "retrieve", after_retrieve, {"grade": "grade", "generate": "generate"}
    )

    builder.add_conditional_edges(
        "grade", after_grade, {"retrieve": "retrieve", "generate": "generate"}
    )

    builder.add_edge("generate", END)

    return builder.compile()
