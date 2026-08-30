# External Review — 2026-08-30 · Remediation Backlog

## What this file is

On 2026-08-30 an external Claude Opus 5 session was shown `CLAUDE.md` and asked for an
unsugarcoated assessment of the project's methodology — weaknesses, blind spots, anything
that could go wrong. It returned a critique organised as P0 / P1 / P2. This file concentrates
that critique into 21 numbered items, each with a severity, a verdict of my own, a concrete
action, and a test for when the item is closed.

**Two items are not from the external review.** Items 4 and 18 are mine, found while checking
the critique against the repository. Both are marked. Everything else traces to the review.

**Repository state when this was written:** `HEAD = c0a4af4` ("chore: license the project under
MIT"). Phase 4 in progress — Steps 4.1, 4.2, 4.2a, 4.3a, 4.3b complete; Step 4.3 fully planned
in `artifacts/step-4.3-per-entity-retrieval.html` but **not yet written in code**. Two unrelated
working-tree edits were uncommitted in `agent/graph.py` and `query/rag.py`.

**Note on `CLAUDE.md`:** it is gitignored (`.gitignore:59`), so its history is *not* in git.
The 2026-08-30 restructure of that file (items 19 and 17) cannot be recovered with `git show`.

---

## How to use this file in a new session

Paste or reference this file alongside `CLAUDE.md`. It is designed so that a fresh session needs
no other context to pick up remediation work:

1. Read **Verified facts** first — those are checked against the repository, not recalled. If a
   session is about to assert one of those facts, it should re-run the command rather than trust
   the number, since the repo moves.
2. Pick the next item whose **Status** is `open`, in the order given under **Recommended order**.
3. Follow the project's normal methodology from `CLAUDE.md` (overview → rationale → concepts →
   code → verification). This file supplies the *what*; `CLAUDE.md` still governs the *how*.
4. When an item closes, change its Status here to `done (YYYY-MM-DD)` and add a one-line note
   saying what actually shipped. Record the reasoning in `NOTES.md` as usual — this file is an
   index, not a journal.

---

## Verified facts

Everything in this section was checked against the repository on 2026-08-30. These are the facts
the backlog rests on, recorded so no future session has to re-derive them or guess.

| Claim | How it was checked | Result |
|---|---|---|
| No held-out question set exists | `ls evals/*.jsonl` | Only `v1_golden_questions.jsonl` and `v2_golden_questions.jsonl`. Both have been scored against repeatedly. |
| Golden v2 pin distribution | Counted `expected_cves` lengths across the file | 50 questions: 24 with one pin, 12 with two, 2 with three, 1 with four, 11 with zero (open-ended, scored `[SKIP]`). So 39 scored. |
| Precision@5 is not comparable across questions | Follows from the line above | A one-pin question caps at 0.20 precision@5. 24 of 39 scored questions are one-pin. |
| Golden set has no product/vendor field | Inspected the JSONL keys | Fields are exactly `id`, `question`, `expected_cves`, `category`, `difficulty`. |
| CPE (affected-product) data is discarded at ingest | `grep -rn "cpe\|configuration" -i --include=*.py src/` | **Zero matches.** `CveDetail` in `nvd_client.py` parses `id`, `published`, `lastModified`, `descriptions`, `metrics`, `references` — the NVD `configurations` array is never parsed. |
| `normalize_cve()` keeps only ID, CVSS and description | Read `ingestion/pipeline.py:18-30` | Returns `f"{cve.id}{severity}\n{description}"`. Nothing else survives into the indexed text. |
| CPE cannot be backfilled locally | Read the first record of `corpus_nvd.jsonl` | The dump holds only `cve_id`, `embed_model`, `published`, `source`, `text` — it is the *normalized* output, not the raw NVD payload. Recovering CPE needs a full re-fetch of ~185k records from the NVD API. |
| Test count and scope | `ls tests/` | Two files: `test_grade.py`, `test_sse.py`. 14 tests, all pure, none crossing the HTTP boundary. |
| `CLAUDE.md` is not version-controlled | `git check-ignore -v CLAUDE.md` | `.gitignore:59`. |
| `artifacts/` is not version-controlled | `git check-ignore -v` / `.gitignore:50-52` | Untracked by design; published copies live as Claude artifacts. |

---

## The backlog

Severity is mine. The external review's own priority band is shown for comparison — where they
differ, the reason is in the item detail.

| # | Issue | Severity | Their band | Status |
|---|---|---|---|---|
| 1 | No held-out question set — every knob tuned on the ruler | **Critical** | P0 | open |
| 2 | `_CODENAME_ALIASES` is fitted to the question set | **High** | P0 | open |
| 3 | `candidates=20` decided by one question moving | Medium | P0 | open (restate only) |
| 4 | Golden v2 was itself rewritten from the failure inventory | **Critical** | *mine* | open |
| 5 | Deliverables verified at the harness, not the product | **Critical** | P0 | open |
| 6 | HTTP-boundary gap filed as a Phase 5 "known gap" | **High** | P0 | open |
| 7 | Tests arrived at Step 4.2, ~25 steps in | Medium | P0 | open |
| 8 | "Provable no-op, no eval re-run" used as a substitute for measurement | Medium | P0 | open |
| 9 | Generation is never measured | **High** | P0 | open |
| 10 | No precision or distractor metric | **High** | P0 | open |
| 11 | The 1.00/1.00/1.00 headline invites the wrong inference | Medium | P0 | open |
| 12 | Latency regressed ~7× undefended; no service-level objective | **High** | P1 | open |
| 13 | Grader non-determinism is load-bearing; ×3 runs are underpowered | **High** | P1 | open |
| 14 | Principle/practice divergence — no LLM routing, but an LLM judge | Medium | P1 | open (blocked by 18) |
| 15 | Two payload overlays silently wiped by any reindex | Medium-High | P1 | open |
| 16 | No adversarial thinking — injection, auth, rate limiting, input bounds | Medium | P2 | open |
| 17 | Stack table overstated (LlamaIndex, Langfuse, Redis) | Low | P2 | **done (2026-08-30)** |
| 18 | CPE / affected-product data discarded at ingest | **High** | *mine* | open (decision needed) |
| 19 | `CLAUDE.md` was operating document plus changelog | Low | P2 | **done (2026-08-30)** |
| 20 | "Code — typed, not pasted" may have quietly lapsed | Self-check | P2 | open (user's call) |
| 21 | Portfolio reframe — held-out 0.78 beats self-authored 1.00 | **High** | P2 | open (follows 1) |

---

## Item detail

Terms used below, defined once. A **held-out set** is a set of questions the system is never tuned
against — it is scored on them, and nothing is changed in response to the result except by
starting a new series. A **service-level objective (SLO)** is a latency budget written down in
advance and treated as a gate, not a report. **Precision@k** is the fraction of the k returned
records that are correct, as opposed to context recall, which is the fraction of correct records
that were returned. A **distractor** is a retrieved record that is wrong but plausible — in this
corpus, usually a vulnerability in a different product. **CPE** (Common Platform Enumeration) is
NVD's structured `vendor:product:version` list of what a CVE actually affects.

### 1 — No held-out question set · Critical · open

**Issue.** Roughly fifteen consecutive design decisions were made while measuring against the same
40 pinned questions: hybrid retrieval, reranking, query rewriting, exact-ID routing, alias routing,
the KEV lanes, the blend weights, the RRF constant, `candidates=20`, grade-and-retry, and the retry
width. There is no set the system has never been tuned against, so the current score is training
accuracy and nothing is known about generalisation.

**My verdict.** Agree — this is the item that invalidates the headline number, and the one a sharp
interviewer finds first, because a perfect score on a self-authored set is a flashing light.

**Action.** Write 30–50 new questions **without opening the failure inventory** — no reading of the
3.7/3.8 failure list, the q43 investigation, or any per-question eval output while authoring.
Corpus-validate them with `evals/validate_golden.py`, freeze them as `v3_holdout_questions.jsonl`,
and run them **once per phase boundary**, never per step. Consider generating part of the set
programmatically by sampling corpus records and writing questions from the record rather than from
memory — but note the trap: questions generated from metadata can be trivially answerable by that
same metadata, so hand-write the question text even when the record is machine-chosen.

**Done when.** A frozen `v3` file exists, has been scored exactly once, and its number is recorded
in `NOTES.md` and the README as a separate series. Expect it to be meaningfully worse than 1.00.

### 2 — `_CODENAME_ALIASES` is fitted to the question set · High · open

**Issue.** The alias table is 20 hand-picked marquee vulnerability nicknames, and three of them
(ProxyLogon, SMBGhost, SIGRed) were added *after* seeing run 1 — disclosed at the time, but still
a lookup table shaped by the questions it is scored on. It moved the easy tier 0.70 → 1.00. On a
question naming a codename outside those twenty, that gain is zero.

**My verdict.** Agree. But the fix is not to delete the table — encoding a closed vocabulary
statically is legitimate domain engineering, and the same reasoning produced the grader's
authentication glossary in 4.2.

**Action.** Report alias coverage as its own number, separate from the tier score: of the codename
questions in the held-out set, what fraction does the table resolve? A routing mechanism with
(say) 60% alias coverage is an honest, defensible result. "Easy 1.00" is not.

**Done when.** The held-out run reports an alias hit rate alongside the tier scores.

### 3 — `candidates=20` decided by one question · Medium · open (restate only)

**Issue.** The 3.8 sweep called depth 20 "strictly dominant", but the only per-question score that
moved across the whole sweep was q31.

**My verdict.** Partly disagree with the review. The *recall* half of that claim does rest on one
question — but the shipped argument was **dominance**: nothing got worse anywhere, and fall-through
p95 fell about 25%. That reasoning survives the overfitting objection, because a latency win does
not depend on the ruler.

**Action.** Keep `candidates=20`. Restate the claim in `NOTES.md` and `CLAUDE.md` as *"cheaper at
equal recall"* rather than *"better recall"*. Re-check it once on the held-out set; if depth 20
loses recall there, that is a real finding.

**Done when.** The wording is corrected and the held-out run confirms no recall loss at depth 20.

### 4 — Golden v2 was itself rewritten from the failure inventory · Critical · open · *my addition*

**Issue.** Step 3.7 did not only re-tune knobs against a fixed ruler — it **reshaped the ruler**
after seeing which questions were failing. q25 was reworded, q43 was reworded, q23 was converted to
open-ended, and four questions had their pin sets expanded. Each individual change was justified on
validity grounds and the reasoning is sound question by question, but the *trigger* for the review
was the failure list.

**My verdict.** I rate this above the knob-tuning in item 1. Re-tuning parameters against a fixed
target is ordinary overfitting and is at least measurable; moving the target after seeing the
results is a stronger form, and it is invisible in the score. This does not mean golden v2 is
wrong — it means golden v2 cannot certify itself.

**Action.** This is the strongest reason item 1's held-out set must be authored blind, and the
reason it must be frozen before it is ever scored. Also add one honest sentence to `NOTES.md` 3.7
and the README recording that the v2 rewrite was prompted by failure analysis.

**Done when.** The disclosure sentence exists, and the held-out set exists and was authored without
consulting any failure output.

### 5 — Deliverables verified at the harness, not the product · Critical · open

**Issue.** Step 4.1 discovered that `POST /v1/query` had been calling naive dense `retrieve()` the
whole time. Phase 2's deliverable ("`POST /v1/query` streams answers ✓") and Phase 3's deliverable
("measured context-recall improvement ✓") were therefore both true in the eval harness and false in
the shipped product, for the entire duration of Phase 3. Every gain from 3.1 through 3.8 lived in a
code path the product did not call.

**My verdict.** Agree, fully. This is a definition-of-done defect, not a bug — the deliverable was
written against the harness and the harness was honest about what it measured.

**Action.** Change the definition of done in `CLAUDE.md`'s methodology: **no step is complete until
the path an actual user hits has been exercised.** This is a one-line change to the methodology
section, and it is what prevents the class rather than the instance.

**Done when.** The methodology's verification step names the product boundary explicitly.

### 6 — HTTP-boundary gap filed as a Phase 5 "known gap" · High · open

**Issue.** The cause was diagnosed correctly — the harness consumes `graph.astream()` in-process and
never crosses the HTTP boundary, so both the 4.1 defect and the 4.2a SSE defect "hid there by
construction" — but the remedy was filed as a Phase 5 known gap.

**My verdict.** Agree, and the *filing* is the error. This is not a coverage gap; it is the
project's demonstrated failure mode, and it has already fired twice.

**Action.** One test that starts the app, POSTs to `/v1/query`, asserts the SSE frame shape (each
`data:` line is a single line of valid JSON, terminated by a blank line, with an unencoded `[DONE]`
sentinel), and asserts that a known routed question returns its pinned CVE. Roughly 30 minutes.

**Done when.** The test exists, runs in CI, and fails if the endpoint is pointed at a stale
retrieval path.

### 7 — Tests arrived at Step 4.2, roughly 25 steps in · Medium · open

**Issue.** The first tests in the repository were written at Step 4.2. There are 14, all pure.

**My verdict.** Agree — this is the root cause of items 5 and 6. Backfilling tests for the whole
history is not worth it now.

**Action.** From here, require at least one test per step, at the boundary the step actually
changes. Add that requirement to `CLAUDE.md`'s methodology alongside item 5's change.

**Done when.** The methodology requires it and the next step ships with a test.

### 8 — "Provable no-op, no eval re-run" as a substitute for measurement · Medium · open

**Issue.** That reasoning appears twice, at 4.2a and 4.3a, to justify skipping an eval run.

**My verdict.** Agree, with a caveat: both instances were, as far as I can tell, genuinely correct.
The problem is that it is the same *kind* of reasoning that let the 4.1 defect survive a whole
phase — arguing that nothing changed instead of observing that nothing changed.

**Action.** Permit the argument only when a test covers the claim. That makes item 6 a prerequisite
rather than a nicety.

**Done when.** The rule is written into `CLAUDE.md` next to items 5 and 7.

### 9 — Generation is never measured · High · open

**Issue.** Context recall scores whether expected CVE IDs appear in *retrieved payloads*. Four
phases in, everything optimised has been retrieval, and the thing the user actually receives has
never been measured — while a known open bug has the model announcing that its context is
insufficient and then answering from training data anyway. A system could retrieve perfectly,
generate confabulated text, and still table 1.00 / 1.00 / 1.00.

**My verdict.** Agree. The Phase 2 decision to score payloads was right at the time and is now
overdue for a companion metric.

**Action.** Faithfulness proper can stay in Phase 5 with Langfuse, but Step 4.4's prompt hardening
must ship with *some* measurement — even 20 questions hand-scored as grounded / ungrounded gives a
number to move. Do not ship 4.4 on the claim that the prompt is better.

**Done when.** 4.4 lands with a generation number, however crude, recorded in `NOTES.md`.

### 10 — No precision or distractor metric · High · open

**Issue.** Context recall rewards surfacing the pinned record and penalises nothing for the four
wrong records sitting beside it. In threat intelligence a wrong CVE in context is not neutral — it
is what the model will cite.

**My verdict.** Agree that it matters. **Disagree that it is free**, which is where I part company
with the review. 24 of the 39 scored questions have exactly one pin, so precision@5 caps at 0.20
for most of the set and is not comparable across questions. Raw precision@5 would produce a number
that looks like a quality score and is really a pin-count artefact.

**Action.** Two options, in order of value:
- *Cheap and partial:* report precision only on the questions whose pin set is closure-defined
  (q24, q25, q30, q31 — where 3.7 defined the pins as the full subset matching the question's
  qualifiers). On those, precision is genuinely meaningful.
- *Right and costlier:* measure a **distractor rate** — the share of retrieved records that are
  about the wrong product. That needs a product label per record, which is item 18.

**Done when.** One of the two ships and is reported alongside recall.

### 11 — The headline invites the wrong inference · Medium · open

**Issue.** "1.00 / 1.00 / 1.00" reads as system quality. It is retrieval-only, on a self-authored
ruler.

**My verdict.** Agree, and this is the cheapest item on the list.

**Action.** One asterisk in `CLAUDE.md` and `README.md`: *this measures retrieval only, on a set the
system was tuned against.* Ten minutes. Do it today; it costs nothing and it is the sentence that
stops a future session — or a reader — from misreading the number.

**Done when.** Both files carry the qualifier at the point the number appears.

### 12 — Latency regressed ~7× undefended · High · open

**Issue.** Retrieval p95 went 4.1 s → 27.6 s → 28.4 s and end-to-end p95 reached about 85 s. This
appears as a single "Cost:" clause in the 4.2 notes and the document moves on. Budget caps are
Step 4.5 — listed, unscheduled, near-last. Accuracy is unconstrained; latency is a residual.

**My verdict.** Agree, with a refinement the review did not make: **an aggregate SLO would be
meaningless here.** Retrieval p50 is about 0.34 s and p95 about 28 s because those are *different
code paths* — the deterministic routed lookup versus the full rewrite-rerank-grade-retry cascade.
A single aggregate gate would be satisfied by the routed majority and would never fire.

**Action.** Write a **per-path** SLO into `CLAUDE.md` as a hard gate — for example routed lookup
p95 ≤ 1 s, fall-through p95 ≤ 10 s, end-to-end p95 ≤ 20 s. Then note honestly that the currently
shipped configuration **fails** the fall-through gate at 28.4 s, and that Step 4.5 is its
remediation. Choosing to run over budget with the number written down is a defensible engineering
position; not noticing is not.

**Done when.** The SLO is in `CLAUDE.md`, the current violation is recorded next to it, and any
future step that worsens it carries a written justification.

### 13 — Grader non-determinism is load-bearing · High · open

**Issue.** The grade node's decisions vary at temperature 0 — a probe measured three discards, then
one, then one, on identical input. Grade-and-retry is now the mechanism carrying q45, q30, q31, q24
and q43. Three runs cannot detect a decision that fires one time in three, so the stability evidence
is underpowered for exactly the failure mode that was found.

**My verdict.** Agree, and the statistical point is the sharpest thing in the review. The q43 caveat
is honest but scoped too narrowly — it reads as one question's footnote when it is a property of the
whole Phase 4 gain.

**Action.** Re-run the five grade-dependent questions ×10 (not the full set — five questions).
Report the spread per question. **Do this before Step 4.3**, because 4.3's entire justification
rests on the 3/1/1 measurement, and ten runs could change what the right fix is.

**Done when.** A ×10 spread is recorded for q24, q30, q31, q43 and q45, and the CLAUDE.md caveat is
rewritten to cover all of them rather than q43 alone.

### 14 — Principle and practice have diverged · Medium · open (blocked by 18)

**Issue.** A tool registry was refused specifically because letting an LLM choose would undo the
deterministic routing Steps 3.4 and 3.5 built. That was the right call. But a stochastic 8B judge
then went into the centre of the graph.

**My verdict.** Agree the tension is real. **Their suggested fix is blocked**, which is the useful
finding: "ask whether a rules-based check beats the grader at wrong-product eviction" cannot be
tried today, because there is no product field to check against. Step 4.3's own rationale says so.
The resolution is item 18, not removing the grader.

**Action.** Do not act directly. Record the tension in `NOTES.md`, and revisit once item 18 is
decided. If CPE data lands, a rules-based product check becomes possible and should be measured
head-to-head against the grader on its one reliable capability.

**Done when.** Item 18 is decided, and the head-to-head is either run or explicitly declined.

### 15 — Two payload overlays silently wiped by any reindex · Medium-High · open

**Issue.** The KEV exploitation flags and the CVSS/severity fields are both `set_payload` overlays.
Any re-ingest or reindex upserts whole points and erases them, with no error and no crash. The
mitigation is a note reminding a human to run two CLI commands.

**My verdict.** Agree, and this is the best ratio of risk removed to effort spent on the list. The
project already wrote the correct description of this hazard for the embedding model: *no error, no
crash, only slowly worse search.* Same category, same silence.

**Action.** Make `reindex_hybrid` invoke both backfills itself, or add a post-reindex assertion on
stamped-record counts that fails loudly. Roughly one hour.

**Done when.** A reindex either restores both overlays automatically or refuses to report success
without them.

### 16 — No adversarial thinking · Medium · open

**Issue.** The corpus roadmap includes vendor advisories and threat reports — untrusted external
prose flowing into an LLM context, a textbook prompt-injection surface — and the document says
nothing about it. `/v1/query` has no authentication, no rate limiting (Redis is in the stack for
exactly this and is unused), and no input size bounds.

**My verdict.** Agree, and one surface is **live today, not prospective**: CVE descriptions are
third-party text written by vendors and researchers, and they flow straight into the context window
already. The exposure is mild because the text is curated and structured, but "we only ingest NVD"
is not the same as "no untrusted text reaches the model".

**Action.** Add a short threat-model section to `CLAUDE.md` or `docs/` even if every mitigation is
deferred to Phase 6: what is untrusted, what it could do, what would stop it. For a security-domain
portfolio the omission reads worse than the gap.

**Done when.** The section exists and names the live surface honestly.

### 17 — Stack table overstated · Low · **done (2026-08-30)**

**Issue.** LlamaIndex was listed as "Retrieval primitives (chunking, indexing)" while appearing in
zero files and zero commits; Langfuse and Redis were listed without noting they have no consumer.

**Closed.** The LlamaIndex row was replaced with FastEmbed and an explicit paragraph recording that
LlamaIndex was deliberately dropped and never imported. Redis and Langfuse are now marked "in
compose, not yet wired in". Two further stale facts were corrected in the same pass: the Ollama row
named unpinned models, contradicting the pinning rule three sections above it, and
`rag_stream()` — deleted in Step 4.1 — was still described in the architectural decisions.

### 18 — CPE / affected-product data discarded at ingest · High · open · *my addition*

**Issue.** The NVD API returns a `configurations` array giving each CVE's affected products in
structured `vendor:product:version` form. `CveDetail` never parses it, `normalize_cve()` never
writes it, and `grep -rn "cpe\|configuration" -i --include=*.py src/` returns zero matches. The
system therefore has no machine-readable notion of what product a record is about.

**My verdict.** This sits underneath three other items, which is why I rate it High despite nobody
having raised it. It is the missing structured field that would let a **rules-based check** do
wrong-product eviction (item 14), let a **distractor rate** be computed without hand-labelling
(item 10), and give **per-entity retrieval lanes** something concrete to filter on (Step 4.3).
Step 4.3's rationale states "there is no product field in the payload to filter on" — true, but
that is a consequence of throwing the data away at ingest, not a fact about the corpus.

**Cost warning, stated plainly.** Unlike Step 4.3a's CVSS backfill, this is **not** a free local
operation. `corpus_nvd.jsonl` holds only the normalized output (`cve_id`, `embed_model`,
`published`, `source`, `text`), so CPE is not recoverable from disk. It requires a full re-fetch of
roughly 185,000 records from the rate-limited NVD API, then a `set_payload` overlay — days of
wall-clock time, though no re-embedding and no vectors moved.

**Action.** This is a decision, not a task. Either commit to the re-fetch as its own step, or
record explicitly that the system will not have product metadata and that items 10 and 14 take
their reduced forms as a result. Do not leave it undecided.

**Done when.** The decision is written down either way.

### 19 — `CLAUDE.md` was doing two jobs · Low · **done (2026-08-30)**

**Issue.** 225 lines, of which the phase checklists were 51.7% of the characters — Phase 3's step
narratives alone were 28.7%. Every session paid context for history read once.

**Closed.** Restructured to an operating document: 35,866 → 18,391 characters, a 49% cut. Phase 1–3
step narratives, completed 4.1–4.3b narratives, both "Resolved (Step …)" entries and the phase
deliverable lines were deleted — all are in `NOTES.md`, `README.md` or the project-structure tree.
Seven standing rules that had been buried *inside* step narratives were extracted into a new
"Active constraints" section rather than deleted with them: the pinned stack, golden v2 as the
ruler, `candidates=20`, metadata-as-soft-signal, the overlay re-run requirement, the ratified brief
deviations, and post-Phase-8 future work. Pre-edit copy was saved to the session scratchpad, which
is temporary — and `CLAUDE.md` is gitignored, so there is no other copy.

### 20 — "Code — typed, not pasted" may have lapsed · Self-check · open

**Issue.** The methodology's third stage says code is shown for the user to type, not paste. The
review asks, fairly, whether that survived Phase 4's volume.

**My verdict.** I cannot verify this from the repository — it is a question about how the sessions
actually ran.

**Action.** The user's call. If it has lapsed, the honest move is to amend the methodology to say
what is really happening, rather than keep a rule that is not being followed. It is the rule doing
the most work for the stated goal of actually understanding the system, so amending it is a real
decision, not a formality.

**Done when.** The rule is either confirmed as still followed or rewritten to match reality.

### 21 — Portfolio reframe · High · open (follows item 1)

**Issue.** The review's closing argument: 1.00 / 1.00 / 1.00 on a self-authored set is a *weaker*
interview asset than 0.78 on a held-out set with four diagnosed failure classes. The perfect score
invites the overfitting question and the honest answer is not flattering. The held-out number
invites the diagnosis question — and the diagnostic work is the strongest thing in this project.

**My verdict.** Strongly agree. This is the most useful sentence in the critique.

**Action.** Once item 1 produces a held-out number, lead the README with it and demote the tuned
number to a clearly-labelled training-set row.

**Done when.** The README's headline is the held-out score.

---

## Recommended order

The review's own ordering is sound. I would change two things: run the grader probe **before**
Step 4.3, because 4.3's justification rests on the measurement it re-checks; and fold the smoke
test in with the held-out set, because a broken product path would corrupt the first held-out run.

| Order | Item(s) | Why here | Rough cost |
|---|---|---|---|
| 1 | **11** — asterisk the headline | Ten minutes, stops the number being misread in the meantime | minutes |
| 2 | **6** — HTTP-boundary smoke test | Retires the highest-frequency defect class before anything is measured on top of it | ~30 min |
| 3 | **1, 4, 2** — author and freeze the held-out set | The blocking scientific problem; must be authored blind | hours |
| 4 | **13** — grade-dependent questions ×10 | Must precede 4.3, whose plan depends on the 3/1/1 result | ~1 hour of runs |
| 5 | **12** — per-path SLO written into `CLAUDE.md` | Before 4.3 makes latency worse | ~30 min |
| 6 | **15** — auto-repair the overlays | Best risk-removed-per-hour on the list | ~1 hour |
| 7 | **5, 7, 8** — methodology amendments | One editing pass, closes three items | ~30 min |
| 8 | **Step 4.3** — per-entity retrieval | Already fully planned; now measurable honestly | per plan |
| 9 | **16** — threat-model section | Cheap, and conspicuous by absence in a security project | ~1 hour |
| 10 | **18** — decide on CPE | A real cost; decide deliberately rather than drift | decision |
| 11 | **10, 9** — distractor rate, then generation measurement | Both shaped by the CPE decision; 9 ships with Step 4.4 | with 4.4 |
| 12 | **3, 21** — restate the depth claim; reframe the README | Follow naturally from the held-out number | ~30 min |
| — | **20** | User self-check, any time | — |

## Open questions for the user

1. **Item 18 — CPE.** Commit to the NVD re-fetch, or accept permanently reduced forms of items 10
   and 14? This shapes several other items and should be decided before Step 4.3 hardens around
   its absence.
2. **Item 20 — typed, not pasted.** Still holding at Phase 4 scale, or should the methodology be
   amended to match what is actually happening?
3. **Tracking `CLAUDE.md`.** It is gitignored, so its history is unrecoverable and this session's
   restructure exists in one place. For a portfolio repository, tracking it would be defensible;
   that is a deliberate call, not an oversight to fix silently.
