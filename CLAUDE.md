# CLAUDE.md — Threat Intel RAG

This file is the **operating document**: methodology, current state, active constraints, architecture. Read it fully before proposing any next step.

It is deliberately *not* a changelog. History lives elsewhere and should be read there, on demand:

- `NOTES.md` — the engineering journal. Every step's rationale, measurements, and what went wrong, and what can be learned.
- `artifacts/` — rich HTML write-ups per step, with diagrams and per-question evidence (gitignored; published copies live as Claude artifacts).
- `evals/archive/` — the immutable eval record: every golden set and per-stage result, with a provenance README.
- `README.md` — the stage-by-stage eval table (baseline → hybrid → rerank → routing → KEV → agent). **Scores are not duplicated here; read them there.**

**Open remediation work lives in `docs/review-2026-08-30-remediation.md`** — 21 numbered items from an external methodology review, each with a severity, a recommended action, and a test for when it is closed. Read it before picking up new work; several items block or reorder the remaining Phase 4 steps.

## What this project is

A production-grade Agentic RAG system that answers threat-intelligence questions over public cybersecurity corpora (NVD/CVE, MITRE ATT&CK, vendor advisories, detection rules, threat reports). Built as a portfolio artifact targeting AI backend engineering roles.

The full project brief is at `docs/project-brief.html`.

## Methodology — never skip this

Every step follows this sequence, in order:
0. **Overview** — a clear picture of what we intend to do (should involve appropriate visual aids - flowcharts, diagrams, images, etc.)
1. **Rationale** — what we're building, explain briefly why was it chosen over other options, and why it's sequenced here
2. **Concepts** — the senior-level "why this works this way"
3. **Code** — shown for the user to type (not paste)
4. **Verification** — exact command, expected output, what failure means

When errors occur: walk through diagnostics, do not hand over the fix directly.

### Plain language — a hard rule, not a preference

This is a learning project. Effort spent decoding phrasing is effort not spent on the engineering, so unexplained jargon is a defect in the explanation, not a style quibble.

- **Define every technical term in one plain sentence the first time it appears in a session.** This includes this project's own shorthand — *routed path*, *fall-through*, *KEV prior*, *blend*, *flap*, *IDF dilution*. Familiar to the codebase is not the same as recalled on sight.
- **Compressed results are jargon too.** Notation like `3 / 1 / 1`, `0.5 ↔ 1.0 flap`, or `rank 6 → 6` states an outcome without describing the experiment that produced it, and only parses for someone who already holds the setup in mind. Describe what was done, then give the numbers.
- **Watch verbs that stand in for a mechanism** — *goes*, *fires*, *lands*, *flips*, *survives*. Say what actually happens: "the grader discards the record", "the graph retrieves a second time with a wider cut".
- **No abbreviations or invented shorthand in diagrams**, ever. Spell the node names out.
- Applies equally to chat replies, NOTES.md entries, and published artifacts.
- Combine with the short-responses rule by **cutting content, not clarity** — one extra explanatory sentence always beats a compact but opaque one.

*(Established 2026-08-02 during Step 4.2; restated as a standing rule 2026-08-20 after the q43 investigation write-up used "dropping 3 / 1 / 1" and "goes every time" without explaining either.)*

## Current status

**Phases 0–3: COMPLETE.** Foundations, ingestion and indexing, naive RAG baseline, retrieval quality.

**Phase 4 — Agentic Layer: IN PROGRESS.** Complete: 4.1 LangGraph substrate · 4.2 grade node plus one wider retry · 4.2a entry-point correctness · 4.3a structured CVSS and publication-date metadata · 4.3b pinned inference stack.

The current agent configuration scores **easy 1.00 / medium 1.00 / hard 1.00** on golden set v2, at 28.4 s retrieval p95 — with the q43 caveat below attached to that top row. The full progression from the 0.05 baseline is the README's eval table.

Remaining in Phase 4:

- [ ] **Step 4.3 — REFINE / per-entity retrieval.** A question naming two products gets one ranked list, and one product takes nearly every slot. This runs one retrieval per named product and merges the lists by taking turns. Targets q43's cross-entity crowding, q31/q24 sibling ranking, and the q50 router-precision fix. It cannot raise the score — every tier already reads 1.00 — it replaces a grader coin flip with a mechanism. **Fully planned in `artifacts/step-4.3-per-entity-retrieval.html`; code not yet written.**
- [ ] **Step 4.4 — GENERATE hardening.** Grounded-only prompting, citations, Pydantic answer schema. Addresses the training-data-leakage issue below.
- [ ] **Step 4.4a — constrained decoding at the grade node.** Add JSON-schema `format` support to `OllamaProvider.generate()` and commit `evals/probe_grader.py`, then re-measure JSON output against line output. Gates whether structured outputs reach the grader at all.
- [ ] **Step 4.5 — Budget caps + checkpointing.**
- [ ] **Step 4.6 — Eval: the `agentic` row.** The planned "KEV-prior escape hatch" is **likely unnecessary** — Step 4.2's grade-and-retry already took q45 from 0.00 to 1.00. Probe the mechanism before deleting the task.

## Active constraints

Standing rules. Each was paid for by a measurement; the measurement is in `NOTES.md` at the step named.

- **The inference stack is pinned — keep it that way (4.3b).** `compose.yaml` names `ollama/ollama:0.30.10`; `config.py` names `llama3.1:8b-instruct-q4_K_M` and `nomic-embed-text:v1.5`. Never revert any of these to `latest` or a bare tag. If a model or runtime genuinely has to change, check the digests reported by Ollama's `/api/tags` first, and treat a changed digest as the start of a **new eval series** — not a continuation of the existing rows. Guard the embedding model hardest: swapping it silently invalidates all 185,477 stored vectors, with no error and no crash, only slowly worse search.
- **Golden set v2 is the ruler (3.7).** The v1 rows are a separate, frozen series and are not comparable to it. Any future fixture must be corpus-validated with `evals/validate_golden.py` before use, against the same validity criterion: every pinned CVE correct for the question *as phrased*, and the pin set not an arbitrary subset of a larger correct set.
- **`candidates=20` is settled — do not re-sweep it (3.8).** Depth 20 beat both 50 and 100 on recall *and* latency. Extra depth admits more same-product crowd, which outvotes the marginal correct record in the final blend. `diagnose_pool.py` deliberately keeps its own depth of 50, so diagnostic ranks stay visible beyond the production cutoff.
- **Structured metadata is a soft signal, never a hard filter (4.3a).** 42.4% of the corpus — 78,580 records — carries no CVSS v3.1 metric at all. Use `cvss_score` / `cvss_severity` / `published` as an extra prefetch lane, the way KEV membership is used in 3.6c. A hard `must` filter would silently discard those records rather than rank them lower.
- **Re-run both payload overlays after any reindex.** `python -m threat_intel_rag.cli ingest-kev` and `... backfill-metadata`. Both write fields onto existing points, and any re-ingest or reindex upserts whole points and silently wipes them. The KEV catalog also grows over time, so periodic re-stamps keep the ranking prior current.
- **No tool registry; REFLECT deferred to Phase 5; structured outputs at the generate boundary only.** A tool registry exists so the LLM picks the tool, which undoes the deterministic routing Steps 3.4 and 3.5 built. REFLECT is gated on the faithfulness measurement, because generation quality is currently unmeasured by construction. Full reasoning: `NOTES.md` → "Phase 4 scope".
- **Post-Phase-8 future work:** an optional web-fresh tool; multi-corpus expansion using per-corpus collections, so the eval series stays valid (LlamaIndex returns for document parsing if long-form corpora are ingested).

### Eval review format — always use this when comparing runs

Aggregate tier scores say *whether* something moved; they never say what or why. For every question whose score changed, and every question still below 1.0, lay out four things together: the **question text**, the **expected CVEs**, the **retrieved CVEs from the previous stage**, and the **retrieved CVEs from the new stage** — then a short deduction naming the mechanism.

The non-pinned records in those lists are where the mechanism is actually visible: which wrong-product record was displaced, which competitor moved up, whether a missing pin was retrieved and then dropped or never retrieved at all. Reading the retrieved lists side by side is what turns "medium went up 0.05" into a diagnosis. (Established in Step 4.2, where it separated four genuine grading gains from one upstream query-rewrite wobble.)

**Harness:** `python evals/run_baseline.py [hybrid|rerank|rewrite|route|agent] [v1|v2] [score]`. The version flag (default `v2`) selects both the golden file and the results file, so a results filename always names its ruler. Live `evals/*_results.jsonl` are gitignored scratch; milestones enter `evals/archive/` by deliberate stage-named copy.

## Known issues — open

- **The q43 caveat — read the top eval row carefully.** q43 reaches 1.00 only because the grade node discards a post-authentication record, which drops the survivor count below `top_k` and triggers the retry that lets the Citrix record in. A direct probe measured that discard decision **varying across identical calls at temperature 0** — three runs on the same five records discarded three records, then one, then one. The row means *"the ceiling is reachable"*, not *"the system scores 1.00"*. Cross-entity crowding is still the underlying weakness, and Step 4.3 is its fix. Full write-up: `artifacts/investigation-q43-anomaly.html`.
- **Training-data leakage in generation.** `OllamaProvider.stream()` will say the context is insufficient and then answer from training data anyway. The eval sidesteps this by scoring retrieved payloads rather than answer text. Prompt hardening is Step 4.4.
- **The eval harness never crosses the HTTP boundary.** It consumes `graph.astream()` in-process, so nothing measures `/v1/query` itself. Two real defects hid there by construction: the API still serving the Phase 2 naive-dense path (found in 4.1), and SSE framing silently dropping multi-line tokens (found in 4.2a). The fix is a CI smoke test asserting the wire format, or a harness mode that goes through the API — Phase 5.
- **The index is a 2014→present subset (~185k records) with coverage gaps.** Some real CVEs are absent entirely (xz `CVE-2024-3094`, SolarWinds `CVE-2020-10148`). Measured corollary: about 29% of in-window KEV entries — 443 of 1,514 — are missing. That is an ingestion ceiling on what retrieval can possibly surface, independent of ranking quality.
- **The grader is weak on qualifiers.** It reliably evicts wrong-product records; it is unreliable on "pre-authentication", on a specific year, and on vulnerability type. Six grader configurations were measured before shipping the current one (batches of five, line output) — see `NOTES.md` 4.2.

## Stack

| Component | Role |
|---|---|
| FastAPI + Uvicorn | HTTP API |
| Celery + RabbitMQ | Async task queue |
| LangGraph | Agent orchestration (Phase 4) |
| Qdrant | Vector database — named dense + BM25 sparse vectors, payload-filtered search |
| FastEmbed | BM25 sparse vectors + `ms-marco-MiniLM-L-6-v2` cross-encoder (ONNX, no torch) |
| PostgreSQL + SQLAlchemy + Alembic | Relational state + migrations |
| Redis | Cache + rate limiting (Phase 6 — in compose, not yet wired in) |
| Langfuse | LLM observability (Phase 5 — in compose, not yet wired in) |
| Ollama | Local LLM (`llama3.1:8b-instruct-q4_K_M` + `nomic-embed-text:v1.5`) |
| Pydantic v2 + pydantic-settings | Validation + config |
| structlog | Structured logging |
| uv | Package + environment management |

**LlamaIndex is named in the brief and was deliberately dropped** — `git log -S` confirms it was never imported in any commit. CVE records are single-chunk documents, so the reader and node-parser layers had nothing to do, and Phase 3's Qdrant-native prefetch, fusion and rank blending would have been hidden behind a retriever abstraction. It returns if long-form corpora are ever ingested.

## Code style — cognitive load

Primary reference: **[zakirullin/cognitive-load](https://github.com/zakirullin/cognitive-load)**. Read it before writing any code.

Core rules we adopt from it:

- **Deep modules over shallow ones.** A `NVDClient` that handles fetching, pagination, and retry in one place is better than three micro-classes that each do one thing. Simple interface, rich internals.
- **No premature abstraction.** Do not create a generic base class or shared utility until there are at least three real, concrete use cases for it. Two similar things are a coincidence. Three is a pattern.
- **Linear code.** Flat async flows and early returns over nested conditions and callbacks. If you need to hold more than four facts in your head to follow a function, it needs to be simplified — not split into more functions.
- **Intermediate variables over complex expressions.** Name the sub-condition, not just the result. `is_rate_limited = ...` is better than an inline compound boolean.
- **Don't split for the sake of splitting.** "Functions should be <15 lines" is a false rule. A 40-line function that reads top-to-bottom is better than five 8-line functions that require jumping around to understand.

Where we diverge from the article:

- **Pydantic models and typed dataclasses are load-reducing, not load-adding.** They encode invariants the type checker can verify, which offloads cognitive work to the toolchain. A well-named Pydantic schema is worth the extra file.

## Key architectural decisions

- **LLM provider abstraction** — `LLMProvider` Protocol with `generate/stream/embed` from day one. Never depend on a concrete provider in the agent or retrieval layers.
- **Ollama-first** — zero token cost during build. Swap to Anthropic/OpenAI only when evals justify it.
- **A CVE ID is a primary key, not a search term** — and a vulnerability codename is an alias for one. Exact-ID and codename routing short-circuit to an indexed lookup before any ranked retrieval runs. 29 of the 50 golden questions take that path, deterministically, in about 0.3 seconds (28 of them scored, plus the open-ended q50 that Step 4.3 will move off it).
- **The cross-encoder is a voter, not a judge** — given final authority over the ordering it demoted correct records. Its rank now enters the same reciprocal-rank blend as the fusion rank and the KEV bonus.
- **Qdrant healthcheck** — the official image has no curl or wget; use the bash `/dev/tcp` TCP check instead.
- **Alembic async** — uses asyncpg for the app, so `env.py` needs async-compatible configuration.
- **`src` layout** — the package lives in `src/threat_intel_rag/`, which prevents importing the uninstalled package during tests.
- **mypy strict + FastAPI** — FastAPI decorators trigger `[misc]`; suppressed per-line with `# type: ignore[misc]`.
- **NvdClient windowed pagination** — the NVD API v2 requires both `pubStartDate` and `pubEndDate` together and rejects ranges over 120 days (sending `pubStartDate` alone returns 503). `iter_cves()` auto-windows in 119-day chunks. The no-date path uses unrestricted pagination.
- **`rag.py` separates retrieval from generation** — `retrieve()` embeds the question and queries Qdrant, `stream_answer()` builds the prompt and streams tokens from pre-fetched hits, and `route_retrieve()` is the full routed cascade. The eval harness and the graph call the same functions, so the two entry points cannot drift apart.
- **The eval scorer uses context recall** — it scores whether the expected CVE IDs appear in the retrieved payloads, not in the answer text. Answer-text scoring is unreliable because of training-data leakage and negation false-positives.

## Development commands

```bash
uv sync --dev                          # install all dependencies
uv run uvicorn threat_intel_rag.app:app --reload   # start API
uv run pytest                          # run tests
uv run pre-commit run --all-files      # lint + typecheck
uv run alembic upgrade head            # run migrations
docker compose up -d                   # start all services
docker compose ps                      # check health
```

## Project structure

```
src/threat_intel_rag/
    app.py              — FastAPI app: health endpoints + POST /v1/query (SSE)
    cli.py              — ingest, search, ingest-kev, backfill-metadata
    config.py           — Pydantic Settings (service DSNs + pinned model names)
    db/models.py        — SQLAlchemy ORM (IngestionRecord)
    ingestion/
        nvd_client.py   — async NVD API client, windowed pagination + retry
        qdrant_setup.py — collection setup, payload indexes, get_client()
        pipeline.py     — normalize → embed → upsert → record
        tasks.py        — Celery task wrapper for background ingestion
        hybrid_index.py — reindex cve_vectors → cve_hybrid (reuse dense, add BM25)
        kev.py          — CISA KEV fetch + known_exploited payload overlay
    llm/
        protocol.py     — LLMProvider Protocol (generate, stream, embed)
        ollama.py       — OllamaProvider concrete implementation
    query/rag.py        — retrieve() + stream_answer() + the full routed cascade
    agent/graph.py      — AgentState + build_graph(): retrieve → grade → generate,
                          conditional edges (routed bypass, capped retry)
tests/
    test_grade.py       — verdict parsing, grade-chunk wiring, ID resolution
    test_sse.py         — SSE framing (JSON payloads, the [DONE] sentinel)
evals/
    v1_golden_questions.jsonl  — original 50-question set (frozen; superseded ruler)
    v2_golden_questions.jsonl  — current ruler (Step 3.7 validity review)
    run_baseline.py            — harness: [mode] [v1|v2] [score]
    validate_golden.py         — asserts every pinned CVE is present in the corpus
    diagnose_pool.py           — where an expected record ranks, at each cascade point
    archive/                   — immutable record + provenance README
docs/project-brief.html — the original brief (frozen; its status line is stale)
alembic/                — migration environment
compose.yaml            — Postgres, Redis, RabbitMQ, Qdrant, Ollama, Langfuse
NOTES.md                — the engineering journal
```
