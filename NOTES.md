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

**The insight — a CVE ID is a primary key and a codename is an alias key, not search terms.** We were forcing exact identifiers through fuzzy ranked retrieval. This is the data-justified case for **query routing** (the two reserved options, now earned): an exact-ID short-circuit (`CVE-\d{4}-\d+` → filter the `cve_id` payload index directly) fixes bucket A deterministically; a static codename→ID alias table fixes bucket B. Hard stays flat because q39/q46 are multi-entity — that is **decomposition** (later numbered Step 3.6), still pending.

**Next:** exact-ID short-circuit — fires only on questions containing a literal ID (q01–q10 + q40), so it recovers the three failing ID lookups (q01/q04/q10) → **easy 0.55 → ~0.70**; the codename bucket (q11/q16–q20) is *not* touched by the ID route and needs the alias table. Introduces query routing as the architecture; then the alias table (3.5), then decomposition (3.6) for the hard tier.

### Step 3.4 — Exact-ID short-circuit (query routing) — COMPLETE

**What we built.** `route_retrieve()` in `query/rag.py`: if the question contains a literal `CVE-\d{4}-\d{4,}` token (case-insensitive, deduped via `_extract_cve_ids()`), fetch those records directly with `exact_id_retrieve()` — a Qdrant `scroll` with a `MatchAny` filter on the `cve_id` payload index (built in 3.1) — and stamp `score=1.0`; otherwise fall through to the full rewrite→rerank cascade. If an extracted ID isn't in the index (coverage gap), the empty exact result also falls through rather than returning nothing. `scroll` not `query_points` because a key fetch has no similarity notion — it's a filter read, not a ranking.

**Result — exactly as predicted: easy 0.55 → 0.70.** q01/q04/q10 (the famous-CVE IDF-dilution failures — ID literally in the query, record buried by quoting competitors) all flipped 0 → 1.0. All eleven ID-routed questions (q01–q10, q40) scored identically across three consecutive eval runs — the routed path has zero variance. Medium 0.25 unchanged (no medium question carries a literal ID). A CVE ID is a primary key; fetching by key beats ranking for it, deterministically and at near-zero cost (no embed, no LLM, no rerank on the routed path).

**New finding — temperature 0 is not fully deterministic.** Disagreements showed up *only on rewrite fall-through questions*, in two distinct patterns: (1) **within-session flap** — q18 (Zerologon) scored 1.0 in one of three route runs, 0.0 in the other two; (2) **cross-session drift** — q41 (Dirty COW vs Dirty Pipe) scored 0.50 in the earlier rewrite eval but 0.00 in *all three* route runs, on the identical code path (q41 has no ID token, so routing never touches it). Stable within a session but different across sessions points at Ollama server state (model reload, batching context) on top of per-request noise. Concept: temp 0 makes decoding *greedy* — deterministic **given identical logits** — but the logits themselves wobble: GPU kernels batch concurrent requests, floating-point addition is non-associative, so summation order varies with server load and can flip a near-tie between top tokens; one flipped token early in the expansion cascades. Temp 0 *shrinks* variance; it does not eliminate it. The Step 3.3 "byte-identical" observation was real but partly lucky.

**Honest scores — as measured across the three route runs: easy 0.70 (0.75 once, via q18), medium 0.25 (stable), hard 0.31 (stable).** Hard's −0.07 vs the rewrite row is q41's cross-session drift, not a routing regression. The eval now has a deterministic core (route path) and a low-variance-but-not-zero LLM stage (fall-through).

**The architecture argument sharpened.** Every question moved off the LLM path onto a deterministic route removes *variance and failure at once*. q18's flapping is literally the alias table's case: `Zerologon → CVE-2020-1472` in a static dict never wobbles.

**Next:** Step 3.5 — codename→ID alias routing (bucket B: q11/q16–q20 → easy ~1.0, and de-flaps q18); then Step 3.6 — query decomposition for the hard tier (q39/q46 multi-entity). *(Numbering note: 3.5/3.6 adopted here; earlier sections call 3.6 "3.3c" — same work.)*

### Step 3.5 — Codename→ID alias routing — COMPLETE

**What we built.** `_CODENAME_ALIASES` in `query/rag.py`: a static dict of 20 marquee named vulnerabilities (Log4Shell, Heartbleed, EternalBlue, Meltdown/Spectre, …) → CVE ID lists. `_extract_alias_ids()` matches each alias against the question with a case-insensitive word-boundary regex (`\b` — so "Ghost" can't fire inside "Ghostcat"), and `route_retrieve()` merges alias-resolved IDs with literal-ID extraction before the exact-ID route. A codename is an alias key to a primary key; an LLM's parametric memory is the wrong tool for a closed, enumerable mapping — 3.3 proved the 8B model *deterministically* fails on exactly these names at temp 0.

**Verification before trusting the table.** Every mapping was checked empirically against the live index before the eval: scroll `cve_hybrid` for each ID and eyeball that the description matches the codename's vulnerability (script kept in session scratchpad). Notable: NVD descriptions almost never contain the codename itself — which is precisely why BM25, dense, *and* the cross-encoder all fail on these questions, and a static table is the only deterministic bridge. Three aliases (ProxyLogon, SMBGhost, SIGRed) were added *after* the first 3.5 eval run surfaced them — disclosed here honestly: they complete a public named-vuln list rather than tune to the eval (all three names appear verbatim in questions), and SIGRed's q32 had been passing only by luck on the LLM fall-through path.

**Result — easy 0.70 → 1.00 (zero variance), hard 0.31 → 0.75 (stable ×3), medium 0.25 → 0.42 (0.33 once).** All 28 routed questions (q01–q20, q28/q29/q32, q39/q40/q41/q44/q46) scored 1.0 in all three runs. The multi-ID prediction landed: comparison questions carrying *two* codenames (q39 Zerologon+PrintNightmare, q41 Dirty COW+Dirty Pipe, q44 POODLE+Heartbleed, q46 BlueKeep+SMBGhost) all resolve both names → `MatchAny` fetches both records deterministically. **This pre-empts Step 3.6's original motivating case (q39) entirely.** q41's cross-session drift is gone — moved onto the deterministic path.

**Correction of an earlier claim.** Step 3.1's "medium is codename comparison questions" was wrong: the codename comparisons live in *hard* (`multi_hop`). Medium is dominated by **product questions** ("What RCE vulnerabilities affect Apache Struts?") — no codename, no ID, nothing for the router to grab.

**The residual failure class is product-recall, and decomposition won't fix it.** Every remaining zero/partial (q21–q27, q30, q31 medium; q42, q43 hard) is a product query: dozens of corpus records legitimately match "vulnerabilities affecting F5 BIG-IP", and ranked retrieval has no *importance* signal to surface the famous exploited CVE the golden set pins. Decomposing q43 yields exactly q27 + q30 — which both score 0. So 3.6 as originally scoped (multi-entity decomposition) is mooted; the remaining gap needs either an importance/KEV signal in the payload, product-aware filtering, or a golden-set validity review for underspecified product questions.

**Known limitation (accepted).** q50 — "What supply-chain compromises *similar to Log4Shell*…" — now short-circuits an open-ended question to the single Log4j record. The router can't distinguish a codename used as a *reference point* from a lookup target. No metric impact (q50 is `[SKIP]`), but it's a real precision/recall trade of keyword routing; the fix (merge exact hits *with* ranked retrieval instead of replacing it, or an agentic router) is deferred to Phase 4.

**Variance check.** All disagreement across the three runs is confined to the fall-through LLM path (q21/q22 flapped 0.5 ↔ 0), consistent with the 3.4 finding. The routed core is deterministic.

### Step 3.6a — Pool diagnostic on the product-recall failures — COMPLETE

**Re-scoping.** Step 3.6's original target (multi-entity decomposition) was mooted by 3.5's multi-ID routing. All 11 surviving failures (q21–q27/q30/q31 medium, q42/q43 hard) are product queries. Three candidate fixes (KEV importance metadata, product filtering, golden-set review) address *different* failure modes, so per the 3.1 method we measured before building: `diagnose_pool.py` upgraded to observe the expected CVE's rank at three points in the production cascade — raw-question RRF pool, augmented-query RRF pool, post-rerank — plus the post-rerank top-5, on the failing questions only.

**Two rows are quiet successes.** q25's `CVE-2021-21972` (post-rerank rank 1) and q24's `CVE-2018-11776` (rank 3) are scoring — those questions sit at 0.5, matching 3.5's "zero/partial". The target is the other 17 rows.

**The 17 failing rows re-cut by mechanism — one disease, three depths.** Every bucket is the same root cause, *no importance prior*, expressed at different depths of the cascade:

- **Reranker demotion** — aug-pool near-top, post-rerank buried: q21 (5→16, 6→11), q22 `CVE-2017-0144` (2→23), q31 (3→45), q42 `CVE-2017-5638` (3→13). q22 and q31 would score *today* if we kept the RRF order and never reranked. Mechanism: the cross-encoder has no IDF and CVE IDs tokenize to near-meaningless subwords, so among 50 same-product descriptions it can't tell the famous record from the rest and shuffles it semi-arbitrarily. This is exactly the failure 3.2 held **score-blending** in reserve for — now data-justified (→ 3.6d).
- **Buried in the crowd** — rank ~30–46 at every stage, no stage ever prefers it: q27 (36/39/39), q30 (38/46/21), `CVE-2018-11776` raw 31/37.
- **Absent** — misses the 50-deep pool entirely: q23 (both), q26 (both), q43 (both), q25's `CVE-2021-22005`. The same-product crowd is larger than the pool. No scoring change can fix this — pool *composition* must change (→ 3.6c).

**Downgraded verdict: "expansion problem".** q24's `CVE-2017-5638` went raw rank 35 → aug-pool ABSENT — the appended expansion pushed it out. Real, but not a rewrite defect: a rank-35 record in a crowded pool is one perturbation from the cutoff either way, and this was a single run on the stochastic path. It does *refine* 3.3's claim that augmentation "can only add noise, never destroy the anchor": true for the anchor *token*, but appended tokens can still reshuffle a marginal record out of a crowded pool.

**Validity wrinkle for the golden set.** q30's post-rerank top-5 already contains `CVE-2021-22893` — a KEV-listed pre-auth Pulse Secure vulnerability that is arguably a correct answer the golden set didn't pin. An importance prior will surface KEV competitors too, so some residual "failures" may be scoring artifacts of pinning one famous CVE where several exist. Golden-set validity review queued for after 3.6c/d.

### Step 3.6b — KEV importance signal stamped into the index — COMPLETE

**Concept — realized vs theoretical.** Every stage we have (BM25, dense, cross-encoder, rewrite) scores *query↔document relevance*, and for product queries dozens of records are genuinely relevant — relevance is saturated. What distinguishes the pinned CVEs is a query-independent **document prior**: the world considers them important. Source: the CISA **Known Exploited Vulnerabilities** catalog — confirmed exploitation in the wild, curated by a third party, machine-readable. KEV membership (~0.7% of CVEs) measures *realized exploitation*; CVSS measures *theoretical severity* — the golden set's "famous" tracks the former. All 15 distinct pinned CVEs in the failing set are KEV members: the signal aligns with the eval essentially perfectly.

**What we built.** `ingestion/kev.py` — fetch the KEV feed, then `set_payload` `known_exploited: true` onto `cve_hybrid` in `MatchAny` batches on the `cve_id` payload index. `set_payload` is a server-side *merge* (unlike `upsert`, which replaces the whole point), so no vectors move and no scroll is needed — cheaper than even the 3.1 reindex trick. Filter-based selection makes KEV entries absent from the corpus a silent no-op. `ensure_kev_index()` adds a `BOOL` payload index for 3.6c's filtered prefetch. CLI: `ingest-kev`. Only the boolean is stamped — `dateAdded`/ransomware fields have no consumer yet; re-stamping is one cheap idempotent command.

**Verified: catalog 1,635 → stamped 1,071; all 15 failing pinned CVEs confirmed stamped.** Shortfall fully attributed: 121 catalog CVEs are pre-2014 (outside the ingestion window); the remaining 443 (~29% of the 1,514 in-window KEV CVEs) are corpus coverage gaps. That rate is consistent with the index being a ~185k subset of the full 2014→present NVD corpus — i.e. KEV CVEs appear to be missing at roughly the corpus's general gap rate, not selectively — but note the comparison rests on an *estimated* NVD total (~250–270k), not an independently verified count.

**Implication worth stating plainly:** ~3 in 10 known-exploited CVEs are unretrievable *at any rank* until corpus coverage improves. That's an ingestion ceiling, not a retrieval problem; the golden set's corpus-validation rule shields the eval from it, but it caps what the system can honestly claim.

**Known limitation (accepted).** The payload overlay is fragile: any future re-ingestion `upsert`s whole points and silently wipes the flag, so `ingest-kev` must re-run after any reindex. Production fix — fold a KEV lookup into the pipeline's normalize step — deferred until ingestion is next touched.

**Next:** 3.6c — KEV-filtered prefetch branches in `hybrid_retrieve()` (reserved lanes: KEV records compete only among themselves for pool entry, fixing the absent bucket). Claim verified by the diagnostic (pool entry), eval row recorded separately; if entry doesn't convert to top-5, that cleanly scopes 3.6d (score-blending / KEV-aware ranking) for the demotion and buried buckets.

### Step 3.6c — KEV-filtered prefetch lanes — COMPLETE

**What we built.** Two additional prefetch branches in `hybrid_retrieve()` (`query/rag.py`) — one dense, one BM25 — each filtered to `known_exploited=true` via `_KEV_FILTER`, each with `limit=top_k`; the two main branches are unchanged (`top_k * 4`, unfiltered). Inside a filtered branch, the 1,071 KEV records compete only among themselves, so a query-relevant KEV record reaches RRF fusion with a strong branch rank regardless of how many non-KEV siblings exist. Because RRF is unweighted, branch *count* is the weighting mechanism: a record found by all four branches sums four reciprocal-rank votes where a non-KEV record can collect at most two. This is a deliberate structural bias toward exploited-in-the-wild records, stated plainly. All retrievers above `hybrid_retrieve()` (rerank → rewrite → route) inherit the change; the exact-ID routed path never calls it and is untouched.

**Claim verified: 6 of the 7 previously-absent rows entered the pool.** Post-change diagnostic on the former absent bucket (caveat: "raw-pool" now also includes the KEV lanes, since `hybrid_retrieve()` changed globally — ranks are not directly comparable to the 3.6a diagnostic):

| CVE (question) | raw-pool | aug-pool | post-rerank |
|---|---|---|---|
| CVE-2022-0847 (q23) | 24 | 25 | 47 |
| CVE-2021-22005 (q25) | 8 | 7 | 28 |
| CVE-2020-5902 (q26) | 6 | **0** | 25 |
| CVE-2022-1388 (q26) | 2 | 2 | 12 |
| CVE-2019-19781 (q43) | 16 | 17 | 30 |
| CVE-2019-11510 (q43) | 5 | 11 | 31 |

**Sole holdout: `CVE-2016-5195` (Dirty COW, q23), still absent from every pool.** Likely cause (plausible mechanism, not verified): within-KEV crowding — KEV itself contains dozens of Linux-kernel privilege-escalation entries (Android, Qualcomm, GPU-driver CVEs), so 5195 must rank top-50 *within the KEV lane* for "linux kernel privilege escalation" and does not, while Dirty Pipe does (rank 24). The reserved lane shrinks the arena; it does not eliminate crowding. q23 is also the weakest question in the golden set — "privilege escalation affecting the Linux kernel" has hundreds of legitimate answers — flagged for the validity review.

**Eval (three runs): easy 1.00 / 1.00 / 1.00 · medium 0.38 / 0.42 / 0.33 · hard 0.81 / 0.81 / 0.81.** Hard 0.75 → 0.81 is the first KEV-attributable eval gain, and it is stable: q42's `CVE-2017-5638` flipped 0 → 0.5 in all three runs. (It sat at post-rerank 13 in the 3.6a diagnostic; the inference — not re-diagnosed — is that the KEV lanes changed pool composition enough that it now survives the re-sort.) Medium is statistically unchanged from 3.5: the same 0.33–0.42 band, driven by the same fall-through flappers (q21 flapped 0 ↔ 0.5, q22 flapped 0.5 ↔ 0). Easy held 1.00, confirming the routed core does not touch this code path.

**Every pool entrant was then demoted by the cross-encoder** — aug-pool → post-rerank: 0 → 25, 2 → 12, 7 → 28, 11 → 31, 17 → 30, 25 → 47. q26 would score 1.0 today on the RRF order alone (both expected CVEs in the aug-pool top-5; the eval scores it 0). The residual failure class has therefore collapsed from three buckets to a single mechanism: the final re-sort gives the cross-encoder absolute authority, discarding both the fusion consensus and the importance prior.

**Next: 3.6d — KEV-aware final ranking.** The diagnostic discriminates between the two reserved designs. Score-blending (cross-encoder + RRF rank, held in reserve since 3.2) alone would rescue the strong-fusion rows (q21, q22, q26, q31) but cannot reach the still-buried ones (q27 ~36, q30 ~38–46, q43 at 11/17, 0847 at 24–25). A KEV term in the final score reaches those, and pools are KEV-sparse enough for it to be nearly surgical. Known cost, already visible: q43's current top-5 contains `CVE-2021-22893` — KEV-listed, Pulse Secure, pre-auth, arguably a correct answer the golden set never pinned — so promoting KEV records makes the golden-set validity review mandatory after 3.6d, not optional.

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
| **route+alias** — codename→ID table feeds exact route | 1.00 | 0.42† | 0.75 | — | — | $0 (local Ollama) |
| **route+alias+KEV lanes** — KEV-filtered prefetch branches | 1.00 | 0.38‡ | 0.81 | — | — | $0 (local Ollama) |

\* Fall-through variance, not a routing effect (temp 0 is low-variance, not zero-variance — see Step 3.4): easy hit 0.75 in one of three runs (q18 flapped within-session); hard's q41 scored 0.50 in the earlier rewrite eval but 0.00 in all three route runs on the identical code path (cross-session drift).

† 0.33 in one of three runs — q21/q22 flapped 0.5 ↔ 0 on the fall-through path. Easy and hard were identical across all three runs; all 28 routed questions have zero variance (see Step 3.5).

‡ Medium varied across all three runs (0.38 / 0.42 / 0.33; 0.38 is the median, no stable value exists) — the same q21/q22 fall-through flap as the route+alias row, so medium is statistically unchanged. Easy and hard were identical across all three runs; hard's 0.75 → 0.81 is q42's `CVE-2017-5638` flipping 0 → 0.5, stable in all three runs (see Step 3.6c).

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

