# Threat Intel RAG

An agentic retrieval system that answers cybersecurity questions over NVD/CVE data, built to be **measured rather than demonstrated**. Every retrieval change in this repo was justified by an eval number, and the failures are documented alongside the wins.

Context recall on a 50-question golden set went from **0.05 / 0.04 / 0.38** (naive vector search) to **1.00 / 1.00 / 1.00**, at $0 inference cost, running entirely on local models.

> **Scope, stated plainly.** This is a single-corpus system: 185,477 NVD CVE records from 2014 onward. The project brief describes a five-corpus system (MITRE ATT&CK, vendor advisories, Sigma rules, threat reports) — those are **not built**, and the reasoning for deferring them is in [Future work](#future-work). There is no authentication, rate limiting, or multi-tenancy yet; those are Phase 6. Phases 0–3 are complete, Phase 4 is in progress.
>
> Full brief: [`docs/project-brief.html`](docs/project-brief.html) · Engineering journal: [`NOTES.md`](NOTES.md)

---

## The result

Context recall measures whether the CVE records a question needs actually reach the model's context window — scored on retrieved payloads, not answer text, because answer-text scoring is unreliable when a model can recite from training data.

| Stage | Easy | Medium | Hard |
|---|---|---|---|
| Naive dense retrieval (baseline) | 0.05 | 0.04 | 0.38 |
| + hybrid BM25 + dense, fused with RRF | 0.55 | 0.04 | 0.44 |
| + cross-encoder reranking | 0.60 | 0.08 | 0.38 |
| + LLM query rewriting (augment, temp 0) | 0.55 | 0.25 | 0.38 |
| + exact-ID and codename→ID routing | 1.00 | 0.42 | 0.75 |
| + CISA KEV importance prior, rank blend | 1.00 | 0.62 | 0.75 |
| *— golden set v2: fixture rewritten after a validity review; rows below are a new series —* | | | |
| Same system, on the honest ruler | 1.00 | 0.86 | 0.81 |
| + LangGraph agent: grade node and one retry | 1.00 | **1.00**\* | **1.00**\* |

\* Reproduced three times, including once after a deliberate model restart — but one question reaches 1.00 only because the grading step discards a record, and that decision was measured *varying* across identical calls (three runs on the same five records discarded 3, then 1, then 1). Read the top row as **"the ceiling is reachable"**, not "the system scores 1.00". Full write-up in `NOTES.md`.

**Latency and cost:** retrieval p50 ≈ 0.34 s (the routed path — a single indexed lookup), p95 ≈ 28 s (the full agent path, including LLM rewriting, grading and a retry). End-to-end p95 ≈ 90 s, dominated by generation on an 8B local model. Cost per query: **$0**.

Three things in that table are worth more than the numbers:

- **The difficulty tiers were inverted at baseline.** Hard questions (0.38) beat easy ones (0.05), because "easy" meant terse lookups like *"What is CVE-2021-44228?"* where the question shares no vocabulary with the record's description, while "hard" meant descriptive comparisons packed with matching technical terms. Vector search retrieves on meaning, not identifiers. That inversion is the entire argument for hybrid search, and it only became visible because a baseline was measured first.
- **Two changes made things worse before they made them better.** Cross-encoder reranking *regressed* the hard tier, and the KEV importance prior cost one question permanently. Both are kept in the table with the reason.
- **The fixture itself was audited and rewritten.** Six questions had pins that were arbitrary subsets of larger correct answer sets — the system was being punished for retrieving equally correct records. Rows before and after that review are not comparable, and are separated accordingly.

---

## How retrieval works

The core insight is that **a CVE ID is a primary key, not a search term**, and a vulnerability codename is an alias for one. Forcing exact identifiers through fuzzy ranked retrieval is what produced the 0.05 baseline.

```
question
   │
   ├─ contains "CVE-2021-44228"?  ──┐
   ├─ contains "Log4Shell"?       ──┤  resolve to IDs → indexed lookup → done
   │                                │  (29 of 50 questions · ~0.3 s · deterministic)
   └─ neither ↓
      LLM query rewrite (temp 0, appended to the original — never replacing it)
         ↓
      four parallel prefetch branches in Qdrant
         ├─ dense vectors        (semantic similarity)
         ├─ BM25 sparse vectors  (exact token match, server-side IDF)
         ├─ dense, KEV-filtered  ─┐ reserved lanes: exploited-in-the-wild records
         └─ BM25, KEV-filtered   ─┘ compete only among themselves for pool entry
         ↓
      Reciprocal Rank Fusion
         ↓
      cross-encoder rerank, blended rather than obeyed:
         1/(60 + fusion_rank) + 1/(60 + cross_encoder_rank) + KEV bonus
         ↓
      top 5
```

**Why routing comes first.** Every question moved onto a deterministic path removes variance *and* failure at once. The 29 routed questions return byte-identical results in every run they have been compared across — spanning three months, two inference-runtime versions, and 185,477 payload rewrites.

**Why the cross-encoder is a voter, not a judge.** Given absolute authority it demoted correct records, because CVE identifiers tokenize into near-meaningless fragments and it cannot distinguish the famous record from fifty similar ones. Treating its ranking as one more vote in the fusion — rather than a final re-sort — recovered those questions.

**Why CISA KEV.** Every ranking stage scores how well a document matches a query, and for a question like *"What RCE vulnerabilities affect Apache Struts?"* dozens of records match equally well — relevance is saturated. What separates the answer people want is a query-independent signal: the world considers it important. KEV membership (~0.7% of CVEs) records *confirmed exploitation in the wild*, curated by a third party, which is a different thing from CVSS's *theoretical severity*.

---

## The agent layer

```
                 ┌──────────────────────────────────────┐
                 │  routed lookup → straight to generate │
                 └──────────────────────────────────────┘
                                   ▲
START ──→ retrieve ───────────────┴──→ grade ──→ generate ──→ END
             ▲                            │
             └────── retry, once ─────────┘
                  (survivors < top_k)
```

A LangGraph state machine wraps the retrieval cascade. Retrieved records are graded against the question's stated conditions in **concurrent batches of five** — batch size turned out to matter more than prompt wording, since the model needs sibling records to contrast against. If too few records survive, one retry re-runs the same search with a wider final cut.

Grading fails **open** by construction: an unreadable verdict yields an empty map, every record defaults to keep, and a broken grader can never burn the retry.

---

## Architecture

```
NVD / CVE REST feed
        │
        ▼
┌─────────────────────────────────────────────┐
│  INGESTION            Celery · RabbitMQ     │
│  fetch → normalize → hash → embed → upsert  │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│  API + AGENT          FastAPI · LangGraph   │
│  POST /v1/query  (SSE token streaming)      │
│  route → retrieve → grade → generate        │
└─────────────────────────────────────────────┘
        │
   ┌────┴─────┬──────────────┬─────────────┐
   ▼          ▼              ▼             ▼
┌────────┐ ┌────────────┐ ┌───────┐ ┌───────────┐
│ Qdrant │ │ PostgreSQL │ │ Redis │ │  Ollama   │
│ dense  │ │ ingestion  │ │ (not  │ │ llama3.1  │
│ + BM25 │ │ CDC table  │ │  yet  │ │ 8B + embed│
└────────┘ └────────────┘ │ used) │ └───────────┘
                          └───────┘
```

Redis and Langfuse run in the compose stack but are not yet wired in; they belong to Phases 5 and 6.

---

## Stack

| Component | Role | Status |
|---|---|---|
| **FastAPI** + Uvicorn | HTTP API, SSE token streaming | in use |
| **Qdrant** | Named dense + sparse vectors, payload-filtered search | in use |
| **LangGraph** | Agent state machine with conditional edges | in use |
| **Ollama** | Local inference — `llama3.1:8b-instruct-q4_K_M`, `nomic-embed-text:v1.5` | in use |
| **FastEmbed** | BM25 sparse vectors + `ms-marco-MiniLM-L-6-v2` cross-encoder (ONNX, no torch) | in use |
| **PostgreSQL** + SQLAlchemy + Alembic | Ingestion CDC table, content hashes, embedding-model versions | in use |
| **Celery** + RabbitMQ | Ingestion task queue | in use |
| **Pydantic v2** + pydantic-settings | Schemas and configuration | in use |
| **Redis** | Caching, rate limiting | Phase 6 |
| **Langfuse** | Tracing, cost, prompt versioning | Phase 5 |

**LlamaIndex was specified in the brief and deliberately dropped.** CVE records are single-chunk documents — one record, one vector — so the reader and node-parser layers had nothing to do, and the retrieval work here (named-vector prefetch, server-side fusion, a custom rank blend) is written directly against Qdrant primitives that a retriever abstraction would have hidden. It comes back if long-form corpora are ever ingested; see [Future work](#future-work).

**The inference stack is pinned to exact versions**, and every eval result file records the runtime version and both model fingerprints. This was not always true: an unpinned runtime was silently replaced mid-experiment, which cost an afternoon of forensics and is written up in `NOTES.md` Step 4.3b.

---

## Getting started

**Prerequisites:** Docker Desktop, Python 3.12+, [uv](https://github.com/astral-sh/uv)

```bash
git clone https://github.com/RoyAbr121/threat-intel-rag.git
cd threat-intel-rag
uv sync --dev

docker compose up -d                  # Postgres, Qdrant, RabbitMQ, Redis, Ollama
uv run alembic upgrade head           # database schema

docker compose exec ollama ollama pull llama3.1:8b-instruct-q4_K_M
docker compose exec ollama ollama pull nomic-embed-text:v1.5
```

Populate the index (this is the long part — embedding 185k records takes hours):

```bash
uv run python -m threat_intel_rag.cli ingest --start-date 2014-01-01
uv run python -m threat_intel_rag.cli ingest-kev            # exploitation flags
uv run python -m threat_intel_rag.cli backfill-metadata     # CVSS + date filters
```

Serve and query:

```bash
uv run uvicorn threat_intel_rag.app:app --reload

curl -N -X POST http://localhost:8000/v1/query \
  -H "Content-Type: application/json" \
  -d '{"question":"What is CVE-2016-5195?"}'
```

Development:

```bash
uv run pytest                          # 14 tests, no services required
uv run pre-commit run --all-files      # ruff, ruff-format, mypy --strict
uv run python evals/run_baseline.py agent v2        # run the eval
uv run python evals/run_baseline.py agent v2 score  # score it
```

---

## Design decisions

**Local-first inference.** Ollama from the first commit, behind an `LLMProvider` protocol with `generate` / `stream` / `embed`. Nothing in the agent or retrieval layers depends on a concrete provider. A weak model surfaces bad retrieval design early instead of hiding it — the query rewriter's failures were only obvious because an 8B model made them loudly.

**Qdrant for filtered search.** Threat-intel queries filter constantly (severity, dates, exploitation status), and Qdrant's payload indexes make that a pre-filter on the graph traversal rather than a post-filter on results. Indexed fields: `cve_id`, `cvss_score`, `cvss_severity`, `published`, `known_exploited`, `source`.

**Reindexing without re-embedding.** Adding sparse vectors to 185k records could have meant hours of re-embedding. Instead the existing dense vectors were scrolled out of the old collection and re-upserted alongside cheaply-computed BM25 vectors — zero API calls, zero inference. The same trick backfilled CVSS and exploitation metadata later.

**Deterministic eval discipline.** Query rewriting is the only stochastic retrieval stage, pinned to temperature 0. Even so, temperature 0 proved *low-variance, not zero-variance* — floating-point summation order shifts with server batching, which can flip a near-tie between tokens. Every reported score is the result of three runs, and disagreement between runs is reported rather than averaged away.

**Golden fixtures are corpus-validated and versioned.** Every pinned CVE is verified present in the index before a set is used; a fixture that isn't in the corpus measures nothing. When the fixture changed, it became v2 and the old rows were frozen as a separate series.

---

## Known limitations

Recorded here because a portfolio that hides these is less credible, not more.

- **The corpus is a subset.** 185,477 records from 2014 onward, not the full NVD catalogue. Roughly 29% of in-window CISA KEV entries are missing — an ingestion ceiling on what retrieval can possibly surface, independent of ranking quality.
- **Answer faithfulness is unmeasured.** The eval scores retrieval, not generation. The model will sometimes state that its context is insufficient and then answer from training data anyway. Prompt hardening and a faithfulness metric are Phase 4/5 work.
- **The grader is inconsistent.** At temperature 0, the grading step gives different answers to identical input. It reliably rejects wrong-product records; it is weak on qualifiers like "pre-authentication" or a specific year. Six grader configurations were measured before shipping the current one.
- **Latency is high.** ~90 s end-to-end at p95, almost entirely local 8B generation. Retrieval alone is ~28 s at p95 on the agent path, driven by the grading calls and the retry.
- **No auth, rate limiting, or multi-tenancy.** Phase 6.
- **The eval never crosses the HTTP boundary.** It calls the graph in-process, so two real API defects hid there — the endpoint serving a stale code path, and SSE framing silently dropping newlines. Both are fixed; the structural gap is Phase 5 work.

---

## Build phases

| Phase | Description | Status |
|---|---|---|
| **0** — Foundations | Repo scaffold, Docker stack, CI, pre-commit | ✅ Complete |
| **1** — Ingestion & Indexing | NVD pipeline → Qdrant, CDC tracking | ✅ Complete |
| **2** — Naive RAG Baseline | `POST /v1/query`, SSE streaming, measured baseline | ✅ Complete |
| **3** — Retrieval Quality | Hybrid search, reranking, routing, KEV prior | ✅ Complete |
| **4** — Agentic Layer | LangGraph graph, grading, retry, budget caps | 🔄 In progress |
| **5** — Observability & Eval | Langfuse tracing, CI regression gate, faithfulness | ⬜ Planned |
| **6** — Production Hardening | OAuth2, rate limiting, multi-tenancy, RFC 7807 | ⬜ Planned |
| **7** — Testing & Optimization | Load tests, semantic cache, coverage | ⬜ Planned |
| **8** — Documentation | Final narrative, one-command demo, postmortem | ⬜ Planned |

---

## Future work

Deferred deliberately, with reasons — not overlooked.

**Multi-corpus ingestion (MITRE ATT&CK, Sigma rules, advisories, threat reports).** The brief's headline example queries need cross-corpus reasoning, and this is the largest single gap. The groundwork exists: every record carries a `source` discriminator, the CDC table is keyed on `(source, external_id)`, and neither assumes CVEs. The design constraint is that new corpora belong in **separate collections** rather than merged into the existing one — merging would change term statistics and invalidate every eval row measured so far. Long-form advisories also need section-aware chunking, which is where LlamaIndex would earn its place.

**A structured-metadata query path.** CVSS scores and publication dates are now indexed and filterable, but nothing queries them yet. When it happens it must be a *soft* signal — an additional prefetch lane, as with KEV — never a hard filter: 42% of the corpus has no CVSS v3.1 metric, and a hard filter would silently discard those records rather than rank them lower.

**No agent tool registry.** The brief specifies one. It was declined: a registry exists so the model can choose which tool to call, which would hand routing decisions back to the 8B model that Phase 3 spent five steps taking them away from. The current router is rule-based and deterministic. Two tools is a coincidence, not a pattern.

**REFLECT node, gated on measurement.** Also specified in the brief, also deferred — generation quality is currently unmeasured by construction, and every other node in this graph earned its place from a diagnostic first. The faithfulness metric comes before the node that would act on it.

---

## Repository layout

```
src/threat_intel_rag/
    app.py              FastAPI: health endpoints + POST /v1/query (SSE)
    cli.py              ingest, search, KEV flags, metadata backfills
    config.py           Pydantic settings — pinned model versions live here
    agent/graph.py      AgentState + the LangGraph state machine
    query/rag.py        the full retrieval cascade (routing → rewrite → hybrid → blend)
    ingestion/          NVD client, pipeline, hybrid reindex, KEV, CVSS backfill
    llm/                LLMProvider protocol + Ollama implementation
    db/models.py        SQLAlchemy ORM (ingestion CDC)
evals/
    v1/v2_golden_questions.jsonl   the fixtures, corpus-validated
    run_baseline.py                harness: [mode] [v1|v2] [score]
    diagnose_pool.py               where does an expected record rank, and when
    archive/                       immutable per-stage results with provenance
tests/                  pure unit tests, no services required
NOTES.md                engineering journal — the reasoning behind every number
```

`NOTES.md` is the most useful file in this repository if you want to know *why* rather than *what*. It records what was tried, what failed, what was measured, and several occasions where a confident claim turned out to be wrong.
