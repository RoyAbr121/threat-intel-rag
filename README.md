# Threat Intel RAG

A production-grade **Agentic RAG system** that answers cybersecurity threat-intelligence questions over public corpora — NVD/CVE records, MITRE ATT&CK, vendor advisories, detection rules, and threat-actor reports.

Built with the engineering discipline of a real platform team: typed, tested, observable, and incrementally delivered.

> Full project brief: [`docs/project-brief.html`](docs/project-brief.html)

---

## What it does

Ingests heterogeneous security data, indexes it into a hybrid retrieval layer, and exposes a stateful agentic query engine via an authenticated HTTP API. The agent reasons about the question, decides which sources to query, performs iterative retrieval with self-grading, and produces cited, auditable answers within enforced time and cost budgets.

**Example queries the system handles:**
- *"What recent vulnerabilities affect Kubernetes 1.28, have public PoCs, and which detection rules cover them?"*
- *"What TTPs has APT29 used against financial services in the last 24 months, mapped to MITRE ATT&CK?"*
- *"Compare remediation guidance across the latest Microsoft Exchange advisories."*

Each requires multi-source retrieval, temporal filtering, and cross-corpus reasoning — a single vector search cannot answer any of them.

---

## Architecture

```
External Sources (NVD · MITRE ATT&CK · Advisories · Sigma Rules · Threat Reports)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│                  INGESTION PLANE                    │
│  Celery Beat → RabbitMQ → Celery Workers            │
│  parse → normalize → chunk → embed → upsert         │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│               API + AGENT PLANE                     │
│  FastAPI ←→ LangGraph Agent ←→ LlamaIndex Retrieval │
│  ROUTE → RETRIEVE → GRADE → REFINE → GENERATE       │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌──────────┐  ┌────────────┐  ┌───────┐  ┌────────┐
│  Qdrant  │  │ PostgreSQL │  │ Redis │  │ Ollama │
│ (vectors)│  │ (state/CDC)│  │(cache)│  │ (LLM)  │
└──────────┘  └────────────┘  └───────┘  └────────┘
                                    ↕
                    Langfuse · OpenTelemetry · Prometheus
```

---

## Stack

| Component | Role |
|---|---|
| **FastAPI** + Uvicorn | Async HTTP API, SSE streaming |
| **Celery** + RabbitMQ | Ingestion task queue, scheduled feed pulls |
| **LlamaIndex** | Document parsing, chunking, hybrid retrieval, reranking |
| **LangGraph** | Agent state machine with checkpointing |
| **Qdrant** | Payload-filtered HNSW vector search, sparse + dense |
| **PostgreSQL** + SQLAlchemy + Alembic | Relational state, ingestion CDC, audit log |
| **Redis** | Semantic cache, rate limiting |
| **Langfuse** | LLM observability — traces, cost, prompt versioning |
| **Ollama** | Local LLM (`llama3.1:8b-instruct` + `nomic-embed-text`) |
| **Pydantic v2** + pydantic-settings | Validation, structured outputs, config |
| **uv** | Dependency and environment management |

---

## Build phases

| Phase | Description | Status |
|---|---|---|
| **0** — Foundations | Repo scaffold, Docker stack, CI, pre-commit | ✅ Complete |
| **1** — Ingestion & Indexing | NVD pipeline → Qdrant index of ≥10k CVEs | ✅ Complete |
| **2** — Naive RAG Baseline | `POST /v1/query`, SSE streaming, eval baseline | ✅ Complete |
| **3** — Retrieval Quality | Hybrid BM25+dense, cross-encoder rerank, query rewriting | 🔄 Next |
| **4** — Agentic Layer | LangGraph loop, tool registry, budget caps | ⬜ Planned |
| **5** — Observability & Eval | Langfuse traces, CI eval regression gate | ⬜ Planned |
| **6** — Production Hardening | Multi-tenancy, OAuth2, rate limiting, RFC 7807 | ⬜ Planned |
| **7** — Testing & Optimization | k6 load tests, semantic cache, ≥80% coverage | ⬜ Planned |
| **8** — Documentation | Final README, one-command demo, incident postmortem | ⬜ Planned |

---

## Getting started

**Prerequisites:** Docker Desktop, Python 3.12, [uv](https://github.com/astral-sh/uv)

```bash
# Clone and install
git clone https://github.com/RoyAbr121/threat-intel-rag.git
cd threat-intel-rag
uv sync --dev

# Start the full infrastructure stack
docker compose up -d

# Run database migrations
uv run alembic upgrade head

# Start the API
uv run uvicorn threat_intel_rag.app:app --reload
```

Health check: `curl http://localhost:8000/health`

```bash
# Run tests
uv run pytest

# Lint and typecheck
uv run pre-commit run --all-files
```

---

## Key design decisions

**LLM provider abstraction** — a `LLMProvider` Protocol with `generate/stream/embed` from the first commit. The agent and retrieval layers never depend on a concrete provider; Ollama runs locally during development, Anthropic/OpenAI slots in when evals justify the cost.

**Qdrant for pre-filtered search** — threat intelligence queries are almost always filtered (by CVSS score, date range, vendor, severity). Qdrant's payload-indexed HNSW performs pre-filtering, which is orders of magnitude faster than post-filtering at scale.

**Postgres CDC table** — every ingested document is tracked with a content hash and embedding-model version. Re-ingestion is idempotent; embedding-model upgrades trigger selective re-indexing without full rebuilds.

**Celery + RabbitMQ over a simple queue** — durable broker with DLQs, priority routing, and Celery Beat for scheduled feed pulls. Temporal is acknowledged as the superior choice for long agent runs specifically; the trade-off is documented.

---

## Repository structure

```
src/threat_intel_rag/
    app.py          — FastAPI app, health endpoints
    config.py       — Pydantic Settings (all service DSNs)
    db/
        models.py   — SQLAlchemy ORM (IngestionRecord CDC table)
alembic/            — async migration environment
docs/
    project-brief.html  — full project specification
compose.yaml        — Postgres, Redis, RabbitMQ, Qdrant, Ollama, Langfuse
pyproject.toml      — dependencies, ruff, mypy, pytest
NOTES.md            — running learning journal
```
