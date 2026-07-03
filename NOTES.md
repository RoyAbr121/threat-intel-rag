## Phase 3 — Retrieval Quality

### Step 3.1 — Hybrid retrieval (BM25 + dense, RRF) — COMPLETE

**What we built.** A second Qdrant collection `cve_hybrid` with named vectors: `dense` (768-dim cosine, the *same* nomic-embed-text embeddings) plus a `bm25` sparse vector with server-side `Modifier.IDF`. Sparse vectors come from FastEmbed `Qdrant/bm25`, which emits raw term frequencies and leaves IDF to Qdrant — so IDF recomputes against whatever is in the collection and subset numbers transfer to the full index. Retrieval fuses both via Reciprocal Rank Fusion (`hybrid_retrieve()` in `query/rag.py`).

**Re-indexed 185k records without re-embedding.** The expensive part of a rebuild is embedding, not fetching. Because Step 3.1 keeps the same embed model, we scrolled the existing dense vectors back out of `cve_vectors`, computed the cheap BM25 sparse vector locally, and upserted both named vectors into `cve_hybrid` (`ingestion/hybrid_index.py`). Zero NVD calls, zero Ollama inference. A separate `dump_corpus()` writes the normalized payloads to a local JSONL artifact for offline/reproducible experimentation (only saves the fetch half — a model change would still require re-embedding).

**Result — the inverted tiers broke** (see eval table): easy **0.05 → 0.55** (+0.50), hard 0.38 → 0.44, medium 0.04 → 0.04 (flat). BM25 exact-token match fixes ID lookups exactly as the Phase 2 hypothesis predicted.

**Why medium stayed flat.** Medium is multi-CVE *comparison* questions phrased with codenames ("Compare Dirty COW and Dirty Pipe"), not IDs. No literal ID token → BM25 contributes nothing → hybrid collapses to plain dense, which is the 0.04 baseline. Hybrid only helps when the query carries a token the embedding can't represent. Medium is now the floor.

**Pool diagnostic (`evals/diagnose_pool.py`).** For each pinned expected CVE, retrieve top-50 and bucket its rank: top-5 / in-pool (5–49) / absent (>50). Across the 54 expected-CVE pairs: **19 already top-5, 16 in-pool below rank 5 (reranking → 3.2 can recover), 19 absent from top-50 (genuine recall miss → 3.3 query rewriting).** The remaining gap splits ~50/50 between ranking and recall — neither step alone closes it.

**Absence is a query problem, not a corpus problem.** `CVE-2017-0144` is absent for q14 but in-pool rank 8 for q40 — same CVE, same index, different phrasing. `CVE-2021-44228` is in-pool for q01 (has the ID token) but absent for q11 (codename "Log4Shell" only). The absent set is dominated by codename/descriptive-only queries — direct evidence that the fix is query rewriting (codename expansion, decomposition), not re-indexing.

**Famous-CVE IDF dilution.** The surviving easy failures are all marquee names (Log4Shell, Heartbleed, Shellshock, EternalBlue, BlueKeep). Their IDs are quoted in hundreds of *other* CVE descriptions ("similar to CVE-2021-44228…"), collapsing BM25 IDF and burying the canonical record. Hidden on the 5k iteration subset (those competitors weren't present), it only surfaced on the full 185k index — validate retrieval on the full corpus, never a convenience subset.

**Methodological caveat.** `hybrid_retrieve` ties prefetch depth to `top_k` (`limit=top_k*4`), so the diagnostic at k=50 searched a 200-deep pool vs the eval's 20-deep pool. The in-pool/absent split is robust (absent = missing from 200 deep), but "top-5" diagnostic verdicts are optimistic vs the k=5 eval (e.g. q21's `CVE-2021-44228` shows top-5 in the diagnostic but scored 0 in the eval). Step 3.2 decouples prefetch from k: retrieve deep (≈50) → rerank → top-5.

**Refactors landed alongside.** `qdrant_setup.get_client()` centralizes client construction with `check_compatibility=False`, resolving the Qdrant client/server version-mismatch `UserWarning` (was an open Phase 2 known-issue). `cve_id` payload index added to `cve_hybrid` (was missing on `cve_vectors`).

**Next:** 3.2 cross-encoder reranking — recover the 16 in-pool pairs first (scoped, measurable in isolation), then 3.3 query rewriting for the 19 codename-absent ones.

### Step 3.2 — Cross-encoder reranking — COMPLETE

**What we built.** `rerank_retrieve()` in `query/rag.py`: pull a deep hybrid pool, score every candidate against the query with a cross-encoder, keep the top 5. It pulls `candidates=50` via `hybrid_retrieve(top_k=50)` → 200-deep prefetch per branch → RRF-fused 50 → reranked to 5. This **decouples prefetch depth from the returned `top_k`**, closing the Step 3.1 caveat (the eval pool was only 20 deep). The CPU-bound rerank call is offloaded with `asyncio.to_thread` so it never blocks the event loop.

**Model — deviation from the brief, on purpose.** The brief names `sentence-transformers`; we used FastEmbed `TextCrossEncoder` (`Xenova/ms-marco-MiniLM-L-6-v2`, imported from `fastembed.rerank.cross_encoder`). Rationale: zero new dependencies (fastembed already powers BM25), no torch (~2 GB saved), ONNX-quantized and CPU-fast — the same inference stack as Step 3.1. Functionally the same MiniLM family the brief intended; the reranking result is equivalent. A reasoned stack decision, not a literal copy of the spec.

**Result — a wash in aggregate, a clean dichotomy underneath.** easy 0.55 → 0.60, medium 0.04 → 0.08, hard 0.44 → **0.38** (regressed). Per-question diff of `hybrid_results.jsonl` vs `rerank_results.jsonl`:

- **Recoveries (5):** q02, q03 (exact ID in query), q40 (+`CVE-2017-0143`, both IDs in query), q24, q42 (vocabulary-rich Struts comparisons). The cross-encoder sharpens relevance exactly where the query carries the matching token.
- **Regressions (3):** q17 (PrintNightmare), q39 (Zerologon + PrintNightmare — lost *both*, which hybrid had at rank 1 & 3), q44 (POODLE + Heartbleed). **Every regression is a codename-only query.**

**Root cause.** The rerank is a *pure re-sort* — it gives the cross-encoder absolute authority and discards the RRF ranking entirely. Where the query token matches (an ID, or rich technical vocabulary), joint encoding wins → recoveries. Where the query is a codename the NVD description never contains, the semantic model confidently scores the correct doc *low* and overrides the lucky dense hit → regressions. The reranker can't see what isn't lexically there — the same blind spot as dense.

**Why we proceed to 3.3 instead of tuning.** Every regression is a codename query — precisely Step 3.3's target. q40 already proves the fix: with the IDs *in* the query, the reranker nails it. Once 3.3 rewrites `Zerologon → CVE-2020-1472`, q39/q17/q44 convert from codename-misses to ID-hits and the reranker will *help* them. So 3.2's regressions are 3.3's job, not a reranker defect. **Score-blending** (combine the normalized CE score with the RRF rank instead of a pure re-sort, to protect a strong first-stage consensus like q39) is held in reserve — apply only if first-stage-override regressions survive 3.3.

**`candidates=50` is provisional, not tuned.** Chosen because the pool diagnostic defined "in-pool" as top-50; it is *not* the result of a sweep. Revisit after 3.3 stabilizes retrieval: sweep 20/50/100 and pick by recall vs latency (cross-encoder cost is linear in `candidates`).

**Next:** 3.3 query rewriting / decomposition — codename → ID expansion. Targets both the 19 absent pairs (recall) and the 3.2 codename regressions (which become ID-in-query, and therefore rerankable).

### Step 3.3 — Query rewriting (LLM expansion, augment-not-replace) — COMPLETE

**What we built.** `rewrite_query()` asks the LLM to expand a terse/codename question into corpus vocabulary + the CVE ID; `rewrite_retrieve()` then retrieves on `f"{question} {expansion}"` through the existing rerank cascade. Result **easy 0.55 / medium 0.25 / hard 0.38** — vs rerank (both deterministic) **medium +0.17, easy −0.05, hard flat**. Medium was the floor tier; we more than tripled it (0.08 → 0.25).

**Two corrections turned a mirage into a real result.** The first-cut design *replaced* the query with the rewrite and ran at the model's default temperature. Both were wrong:

- **Non-determinism broke eval integrity.** Every other retriever (dense/hybrid/rerank) is deterministic, so their deltas are trustworthy. The LLM rewrite is the *only* stochastic stage — re-running the same eval moved the numbers, and the diagnostic rewrite of one question (`CVE-2016-5195`) returned a *different, wrong* CVE on each call (once `CVE-2017-5753 / Spectre`, once `SMBv3 RCE`). Fix: a `temperature` param on `LLMProvider.generate`, pinned to `0.0` for the rewrite. A rewrite is a *transformation*, not a *generation* — same input must give same output. Two consecutive evals came back byte-identical. *(Correction, found during the routing step: temp 0 shrinks the variance but does not eliminate it — see the non-determinism finding in the next section. Those two identical runs were real but partly lucky.)*
- **Replace threw away a good query.** The first-cut replace-mode run (default temperature) scored easy **0.50** — a regression from rerank's 0.60 that triggered the diagnosis. Three failure modes showed up in the rewrites: (1) **mangled ID** — `CVE-2020-1472` → `cve 2020-1472`, splitting the BM25 exact-match token; (2) **vocab dilution** — ID kept but added common terms pulled in competitors; (3) **hallucination** — `CVE-2020-1472` (Netlogon) expanded to "Windows remote desktop" (that's BlueKeep). All three argue for **augment, not replace**: appending the expansion preserves the original's correct tokens, so a mangled/hallucinated expansion can only *add* noise, never destroy the anchor. Switching to **augment + temp 0** brought easy back to **0.55** (the final figure). The clean, model-independent guarantee is for questions that *already contain the ID* (e.g. **q08**); codename recoveries like **q13/q15** have no original ID to preserve and instead depend on the temp-0 rewrite mapping the name correctly. Caveat: temperature→0 and replace→augment changed in the *same* step, so per-question replace-vs-augment deltas are confounded — only the structural ID-bearing claim is clean.

**Residual failures are structured-lookup problems, not retrieval problems.** With the eval now deterministic, the surviving easy zeros split cleanly and neither bucket is fixable by more rewriting or tuning:

- **(A) Famous-CVE IDF dilution** — q01, q04, q10. These three *literally contain* the CVE ID (`"What is CVE-2016-5195?"`) and augmentation *kept* it, yet the record stays buried: marquee IDs (`CVE-2021-44228`, `CVE-2016-5195`, `CVE-2022-22965`) are quoted across hundreds of other descriptions, so their IDF collapses and the token stops discriminating. A **ranking** failure.
- **(B) Codename gap** — q11 (Log4Shell), q16 (Dirty COW), q17 (PrintNightmare), q18 (Zerologon), q19 (PwnKit), q20 (Spring4Shell). No literal ID in the query; at temperature 0 the LLM *deterministically* fails to map these codenames to IDs — its parametric recall doesn't cover them.

**The insight — a CVE ID is a primary key and a codename is an alias key, not search terms.** We were forcing exact identifiers through fuzzy ranked retrieval. This is the data-justified case for **query routing** (the two reserved options, now earned): an exact-ID short-circuit (`CVE-\d{4}-\d+` → filter the `cve_id` payload index directly) fixes bucket A deterministically; a static codename→ID alias table fixes bucket B. Hard stays flat because q39/q46 are multi-entity — that is **3.3c decomposition**, still pending.

**Next:** exact-ID short-circuit — fires only on questions containing a literal ID (q01–q10 + q40), so it recovers the three failing ID lookups (q01/q04/q10) → **easy 0.55 → ~0.70**; the codename bucket (q11/q16–q20) is *not* touched by the ID route and needs the alias table. Introduces query routing as the architecture; then the alias table, then 3.3c decomposition for the hard tier.

### Step 3.4 — Exact-ID short-circuit (query routing) — COMPLETE

**What we built.** `route_retrieve()` in `query/rag.py`: if the question contains a literal `CVE-\d{4}-\d{4,}` token (case-insensitive, deduped via `_extract_cve_ids()`), fetch those records directly with `exact_id_retrieve()` — a Qdrant `scroll` with a `MatchAny` filter on the `cve_id` payload index (built in 3.1) — and stamp `score=1.0`; otherwise fall through to the full rewrite→rerank cascade. If an extracted ID isn't in the index (coverage gap), the empty exact result also falls through rather than returning nothing. `scroll` not `query_points` because a key fetch has no similarity notion — it's a filter read, not a ranking.

**Result — exactly as predicted: easy 0.55 → 0.70.** q01/q04/q10 (the famous-CVE IDF-dilution failures — ID literally in the query, record buried by quoting competitors) all flipped 0 → 1.0. All eleven ID-routed questions (q01–q10, q40) scored identically across three consecutive eval runs — the routed path has zero variance. Medium 0.25 unchanged (no medium question carries a literal ID). A CVE ID is a primary key; fetching by key beats ranking for it, deterministically and at near-zero cost (no embed, no LLM, no rerank on the routed path).

**New finding — temperature 0 is not fully deterministic.** Disagreements showed up *only on rewrite fall-through questions*, in two distinct patterns: (1) **within-session flap** — q18 (Zerologon) scored 1.0 in one of three route runs, 0.0 in the other two; (2) **cross-session drift** — q41 (Dirty COW vs Dirty Pipe) scored 0.50 in the earlier rewrite eval but 0.00 in *all three* route runs, on the identical code path (q41 has no ID token, so routing never touches it). Stable within a session but different across sessions points at Ollama server state (model reload, batching context) on top of per-request noise. Concept: temp 0 makes decoding *greedy* — deterministic **given identical logits** — but the logits themselves wobble: GPU kernels batch concurrent requests, floating-point addition is non-associative, so summation order varies with server load and can flip a near-tie between top tokens; one flipped token early in the expansion cascades. Temp 0 *shrinks* variance; it does not eliminate it. The Step 3.3 "byte-identical" observation was real but partly lucky.

**Honest scores — as measured across the three route runs: easy 0.70 (0.75 once, via q18), medium 0.25 (stable), hard 0.31 (stable).** Hard's −0.07 vs the rewrite row is q41's cross-session drift, not a routing regression. The eval now has a deterministic core (route path) and a low-variance-but-not-zero LLM stage (fall-through).

**The architecture argument sharpened.** Every question moved off the LLM path onto a deterministic route removes *variance and failure at once*. q18's flapping is literally the alias table's case: `Zerologon → CVE-2020-1472` in a static dict never wobbles.

**Next:** codename→ID alias table (bucket B: q11/q16–q20 → easy ~1.0, and de-flaps q18); then 3.3c decomposition for the hard tier (q39/q46 multi-entity).

## Phase 2 — Naive RAG Baseline

### Step 2.5 — Baseline evaluation

**Golden set.** 50 questions (20 easy / 18 medium / 12 hard) in `evals/golden_questions.jsonl`. 40 are pinned with expected CVE IDs; 10 are open-ended (no pinned CVEs — they exercise open retrieval and answer quality, and are excluded from the recall metric, shown as `[SKIP]`). Every pinned CVE was validated to exist in the `cve_vectors` index via `evals/validate_golden.py` **before** locking the set — a fixture that isn't in the corpus measures nothing.

**Metric — context recall.** Per question: `|expected ∩ retrieved| / |expected|`, macro-averaged within each difficulty. We score whether expected CVE IDs appear in the retrieved chunk payloads (top-k = 5), *not* in the answer text — answer-text scoring is unreliable due to (a) Ollama training-data leakage and (b) negation false positives. Fractional rather than binary all-present, so partial multi-CVE hits will register Phase 3 gains.

### Eval iteration table

| Version | Easy recall | Medium recall | Hard recall | Faithfulness | p95 latency | Cost/query |
|---|---|---|---|---|---|---|
| **baseline** — naive dense, top-5 | 0.05 | 0.04 | 0.38 | — | — | $0 (local Ollama) |
| **hybrid** — BM25+dense RRF, top-5 | 0.55 | 0.04 | 0.44 | — | — | $0 (local Ollama) |
| **rerank** — hybrid → cross-encoder (MiniLM), top-5 | 0.60 | 0.08 | 0.38 | — | — | $0 (local Ollama) |
| **rewrite** — LLM augment (temp 0) → rerank, top-5 | 0.55 | 0.25 | 0.38 | — | — | $0 (local Ollama) |
| **route** — exact-ID short-circuit, else rewrite | 0.70* | 0.25 | 0.31* | — | — | $0 (local Ollama) |

\* Fall-through variance, not a routing effect (temp 0 is low-variance, not zero-variance — see Step 3.4): easy hit 0.75 in one of three runs (q18 flapped within-session); hard's q41 scored 0.50 in the earlier rewrite eval but 0.00 in all three route runs on the identical code path (cross-session drift).

> Fill the baseline row from `uv run python evals/run_baseline.py` then `… score`. Faithfulness / p95 / cost columns land in Phases 3 and 5; later rows: hybrid → rerank → agentic → cached.

**Learnings:**

- Naive dense retrieval misses exact CVE-ID lookups — the question embedding ("What is CVE-2021-44228?") diverges from the description embedding, so the right record isn't in the top-k even though it's indexed. This is the core problem Phase 3 (hybrid BM25 + dense, exact-match) exists to solve.
- **The difficulty tiers are inverted at baseline: hard (0.38) >> easy (0.05) ≈ medium (0.04).** This is the headline baseline finding. Easy questions are terse lookups/named-vuln ("What is CVE-2021-44228?", "Which CVE is BlueKeep?") where the query is dominated by an ID token or a codename that shares *no vocabulary* with the NVD description, so dense similarity is near-random. Hard questions are descriptive comparisons ("Compare POODLE and Heartbleed as SSL/TLS vulnerabilities", "container escape by overwriting runc") packed with exactly the technical terms that *do* appear in the descriptions, so dense retrieval works far better. Dense embeddings retrieve on *semantic vocabulary overlap*, not on identifiers — which is precisely why Phase 3 adds sparse/BM25 (exact token match for IDs and codenames) alongside dense. The inversion is the single most compelling motivation for hybrid retrieval in the whole project.
- Golden fixtures must be corpus-validated, not assumed. The index is a 2014→present *subset* with coverage gaps — xz `CVE-2024-3094` and SolarWinds `CVE-2020-10148` are both absent, so two drafted questions had to be reworked against confirmed-present CVEs.
- `cve_id` has no payload index (only `source` / `embed_model` do). Fine for the validator's one-off scan; Phase 3 exact-match / hybrid retrieval will want an index on it.
- Duplicate expected CVEs across near-identical questions produce *correlated* votes: they inflate the tier denominator without adding independent retrieval signal, and they overstate later gains (one fix moves three questions at once). Reuse a CVE only across *distinct retrieval modalities* — literal-ID lookup vs name→ID mapping vs product query vs multi-CVE comparison — which hit or miss independently and so each carry real signal.

## Phase 1 — Ingestion & Indexing

- Alembic autogenerate compares ALL tables in the target database against your models. If another tool (Langfuse, in our case) shares the same Postgres database, its tables appear as "to be dropped." Fix: add an `include_object` guard in `env.py` to skip tables not in our metadata, and give each service its own database.

- `docker compose restart` does NOT reload environment variables from compose.yaml — it restarts the container with the same config. Use `docker compose up -d --force-recreate` to pick up config changes.

- NVD API CVSS scores are nested inside a `cvssData` sub-object, not at the top level of the metric entry. Autogenerate your Pydantic models from a real API response, not from documentation alone.

- `func.now` (SQLAlchemy) is a factory object. `func.now()` is the SQL expression. `server_default` requires the expression — passing the factory silently fails at runtime, not at definition time.

- `Mapped[DateTime]` vs `Mapped[datetime]`: the type inside `Mapped[]` is the Python type you get at runtime, not the SQLAlchemy column type. Always use Python's `datetime.datetime` inside `Mapped[]`.

- `uv sync --dev` installs `[dependency-groups]` (PEP 735). `uv sync --extra dev` installs `[project.optional-dependencies]`. They are different sections. Prefer `[dependency-groups]` for dev tools so `--dev` works as expected.

- Pre-commit hooks receive explicit file lists from pre-commit, which bypasses ruff's `exclude` config in pyproject.toml. Fix: add `exclude: ^alembic/versions/` directly to the hook config in `.pre-commit-config.yaml`.

- `struct.unpack(">Q", digest[:8])[0]` converts the first 8 bytes of a SHA-256 digest to a uint64. Used to map string CVE IDs to Qdrant's integer point IDs deterministically.

## Phase 0 — Foundations

- Qdrant's official Docker image ships with no HTTP tools (no curl, no wget). Healthcheck falls back to bash `/dev/tcp` — a TCP-level port check rather than HTTP. Trade-off: we verify the port is open, not that the HTTP layer is healthy. Good enough for dev; production would use a sidecar with curl.
    
- `pydantic-settings` reads config in priority order: env vars > .env file > field defaults. Same code works locally and in Docker — no code changes between environments.

