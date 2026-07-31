from typing import TypedDict

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from qdrant_client.models import ScoredPoint

from threat_intel_rag.llm.protocol import LLMProvider
from threat_intel_rag.query.rag import route_retrieve, stream_answer


class AgentState(TypedDict, total=False):
    question: str
    top_k: int
    hits: list[ScoredPoint]
    answer: str


def build_graph(provider: LLMProvider) -> CompiledStateGraph[AgentState]:
    async def retrieve_node(state: AgentState) -> AgentState:
        hits = await route_retrieve(state["question"], provider, state.get("top_k", 5))

        return {"hits": hits}

    async def generate_node(state: AgentState) -> AgentState:
        writer = get_stream_writer()
        tokens: list[str] = []

        async for token in stream_answer(state["question"], state["hits"], provider):
            writer(token)
            tokens.append(token)

        return {"answer": "".join(tokens)}

    builder = StateGraph(AgentState)
    builder.add_node("retrieve", retrieve_node)
    builder.add_node("generate", generate_node)
    builder.add_edge(START, "retrieve")
    builder.add_edge("retrieve", "generate")
    builder.add_edge("generate", END)

    return builder.compile()
