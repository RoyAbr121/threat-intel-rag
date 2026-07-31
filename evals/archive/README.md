# Eval archive — frozen golden sets and results

Immutable snapshots of every committed eval artifact, extracted from git history.
The live files in `evals/` are overwritten by each run; these copies are the
permanent record. Do not regenerate or edit files in this directory.

Each results file is self-contained: every line embeds both `retrieved_cves` and
`expected_cves` as they were at run time, so scores are reproducible from the file
alone (no golden-set file needed).

Committed results are **single runs**. Fall-through (LLM-path) questions carry
low-but-nonzero variance (see NOTES.md Steps 3.4–3.6d), so a file's medium score
may sit anywhere in its documented band — the per-file scores below are what
*these exact files* contain.

## Golden sets

| File | Source commit | Notes |
|---|---|---|
| `v1_golden_questions.jsonl` | `6d79384` (Step 2.5) | Original 50-question set (20 easy / 18 medium / 12 hard) |
| `v2_golden_questions.jsonl` | `a989244` (Step 3.7) | Validity review: q23 → open-ended; q24/q30/q31 multi-pinned; q25/q43 reworded |

v1 and v2 scores are separate series — never compare across the boundary.

## v1 results (scored against v1 golden set)

| File | Source commit | Stage | easy / medium / hard |
|---|---|---|---|
| `v1_baseline_results.jsonl` | `6d79384` | 2.5 naive dense | 0.05 / 0.04 / 0.38 |
| `v1_hybrid_results.jsonl` | `a901787` | 3.1 BM25+dense RRF | 0.55 / 0.04 / 0.44 |
| `v1_rerank_results.jsonl` | `0b1abb5` | 3.2 cross-encoder | 0.60 / 0.08 / 0.38 |
| `v1_rewrite_results.jsonl` | `b3067f8` | 3.3 LLM augment | 0.55 / 0.25 / 0.38 |
| `v1_route_results_3.4_exact_id.jsonl` | `b3067f8` | 3.4 exact-ID route | 0.70 / 0.25 / 0.31 |
| `v1_route_results_3.5_alias.jsonl` | `c6cae07` | 3.5 alias route | 1.00 / 0.33 / 0.75 |
| `v1_route_results_3.6c_kev_lanes.jsonl` | `f947586` | 3.6c KEV prefetch lanes | 1.00 / 0.33 / 0.81 |
| `v1_route_results_3.6d_kev_blend.jsonl` | `2e6313b` | 3.6d KEV-aware blend | 1.00 / 0.67 / 0.75 |

## v2 results (scored against v2 golden set)

| File | Source commit | Stage | easy / medium / hard |
|---|---|---|---|
| `v2_route_results_3.7_reanchor.jsonl` | `a989244` | 3.7 re-anchor, candidates=50 | 1.00 / 0.83 / 0.81 |
| `v2_route_results_3.8_candidates20.jsonl` | `bc1f7bc` | 3.8 shipped, candidates=20 | 1.00 / 0.86 / 0.81 |
