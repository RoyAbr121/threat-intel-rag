## Phase 2 — Naive RAG Baseline

### Step 2.5 — Baseline evaluation

**Golden set.** 50 questions (20 easy / 18 medium / 12 hard) in `evals/golden_questions.jsonl`. 40 are pinned with expected CVE IDs; 10 are open-ended (no pinned CVEs — they exercise open retrieval and answer quality, and are excluded from the recall metric, shown as `[SKIP]`). Every pinned CVE was validated to exist in the `cve_vectors` index via `evals/validate_golden.py` **before** locking the set — a fixture that isn't in the corpus measures nothing.

**Metric — context recall.** Per question: `|expected ∩ retrieved| / |expected|`, macro-averaged within each difficulty. We score whether expected CVE IDs appear in the retrieved chunk payloads (top-k = 5), *not* in the answer text — answer-text scoring is unreliable due to (a) Ollama training-data leakage and (b) negation false positives. Fractional rather than binary all-present, so partial multi-CVE hits will register Phase 3 gains.

### Eval iteration table

| Version | Easy recall | Medium recall | Hard recall | Faithfulness | p95 latency | Cost/query |
|---|---|---|---|---|---|---|
| **baseline** — naive dense, top-5 | 0.05 | 0.04 | 0.38 | — | — | $0 (local Ollama) |

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

