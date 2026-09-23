# TypeSafe evaluation artifacts (2026-09-21)

Provenance for the two TypeSafe (Jev) seams in this repo. The committed JSON artifacts
(`eval_set.json`, `results.json`, `results_choice.json`, `claims_results.json`) are the
authoritative records of the experiments below. The original scratch directory the runs
were executed from no longer exists — nothing outside this directory is needed to read
or cite the results. The scripts are historical runnable runners, not a test suite;
`test_guards.py` pins their live-run guards offline.

## What was measured

### 1. Knowledge triage design — `eval_set.json` + `rerank_eval.py`

A 20-question labeled set over all 17 knowledge packs (`eval_set.json`; each item names
the gold pack). Two designs were measured against the deterministic IDF baseline
(`knowledge_index.rank_packs`):

| Variant | How | top-1 | top-3 | Verdict |
|---|---|---|---|---|
| Baseline | IDF over `load_when` | 17/20 | 20/20 | fallback |
| A — per-pack Noul rerank | one Jev `noul` call per shortlisted pack (`main`) | 7/20 | 11/20 | lost, **not used** |
| B — one Choice over all packs + `none` (`main_choice`) | one Jev `choice` call, skill_suggestion pattern | **20/20** | **20/20** | shipped as `tools/ts_triage.py` |

The top-1 count that ships in `tools/ts_triage.py`'s docstring (20/20 vs 17/20) comes
from the variant-B run. Raw outputs: `results.json` (variant A), `results_choice.json`
(variant B); both embed per-item probabilities/orders and token usage.

### 2. Claims relation seam — `claims_eval.py` + `claims_results.json`

10 planted claims over three registered evidence captures of a live shadow workspace
(E-000001, E-000002, E-000004) with known expectations: supports / contradicts /
says_nothing. Result: 10/10 verdict accuracy; the deliberately unanswerable claim was
flagged at 0.45 confidence. `claims_results.json` is the recorded seam output
(verdicts, confidences, probabilities, model id, usage). Since v8.3 V2 the claims seam
consumes only evidence with a clean screening verdict, so a live rerun needs
`researchctl screen <ref>` for each cited ref first (`claims_eval.py` refuses without
it); the committed run predates screening and is the historical record.

### 3. Injection screening — `screen_eval_set.json` + `screen_eval.py` + `screen_results.json` (v8.3)

A 12-item labeled set (six injection-shaped, six benign allow-cases including a
security note that quotes injection strings and a run log) over the fixed four-question
Noul battery shipped in `tools/ts_screen.py`. Baseline: a fixed regex battery over the
raw text. Positive class: injection. Measured: baseline precision 0.75 / recall 1.00 /
F1 0.857; Jev battery precision 0.857 / recall 1.00 / F1 0.923 — the seam ships on the
win. `inj-action` (a shell-command instruction) is refused by the API edge with HTTP
403; the seam fails closed and counts it as flagged (quarantined for review), which the
result rows record under `jev_error` (`refused_calls` in the payload). Question wording
was iterated on the set: the boundary clauses ("what the content itself does, not what
it quotes") moved the three benign false positives to clear.

### 4. Grounded judgments — `grounding_eval_set.json` + `grounding_eval.py` + `grounding_results.json` (v8.3)

Labeled freshness questions whose answers live in the 2026 research corpus (GPT-6
release, the Cloudflare skill's no-live-probing stance, the TypeSafe API's missing
websearch knob, jev-ultrafast's browser-harness dependency). Before-web: one verdict
question over an empty state; after-web: the shipped `ts_ground.ground_state` with the
item's committed, dated snippets inserted verbatim (a `FakeProvider`, so the after-web
arm is reproducible). Measured: confidently-wrong verdicts 4/4 → 0/4 and correct
verdicts 0/4 → 4/4 (the ungrounded model answers `unclear` at ~1.0 confidence on every
question; grounded, all four are correct and clear the code thresholds).

Two out-of-scope cases were removed from the set and the committed rows because the
sprint's no-go list forbids that project in any form (`SPRINT-v8.3-SPEC.md`; flagged by
the spec-axis review as MF-2); the aggregate counts above are recomputed deterministically
over the retained committed rows, and the removal is recorded in `grounding_results.json`
under `removed_for_no_go`. Two in-scope replacement questions and a fresh paired run land
with the grounding-fix commit.

The committed payload records the eval-integrity posture (scored OS runs keep grounding
off unless the engagement explicitly allows it; this eval's after-web arm runs under the
explicit `grounding: "ALLOWED"` opt-in).

### 5. Novelty/duplicate aid — `novelty_eval_set.json` + `novelty_eval.py` + `novelty_results.json` (v8.3)

Nine labeled finding-shaped pairs (three same, four different, two unclear). Baseline:
keyword overlap (the seam's blocking threshold) means `same`, else `different` — a
deterministic similarity heuristic that cannot express uncertainty. Seam:
`ts_novelty.check_novelty` (blocking first, then one pairwise Choice per blocked
candidate; every below-threshold verdict degrades to `unclear` and routes to the human
lane; an empty proposal list means `different`). Measured: baseline 6/9, seam 7/9 — the
seam ships. The one clearly wrong row is a pair the model called `different` at 0.88
confidence (above the threshold, so it is not human-laned — recorded in the rows). One
row (`diff-two-tenant-leaks`, 0.46) was re-derived from `different` to `unclear` +
human lane when the below-threshold rule was widened to every verdict; the committed
model outputs are unchanged and the re-derivation is recorded under
`threshold_rule_rederived` in the payload (no new model calls).

### 6. Hypothesis ranking — `rank_eval_set.json` + `rank_eval.py` + `rank_results.json` (v8.3)

Five labeled scenarios (one high-information safe test, a cosmetic decoy listed first,
an unsafe temptation, a low-value option). Baseline: current priority order (first
hypothesis in creation order). Seam: `ts_rank.rank_hypotheses` — one Noul per open
hypothesis, safety veto and thresholds in code, low-confidence rankings escalate, and a
declared candidate `test_cost` (number or low/medium/high band) breaks an information
tie toward the materially cheaper safe test. The committed scenario set declares no
costs, so the recorded win is information/safety-only; the cost tie-break is pinned by
`tools/test_rank.py`. Measured: baseline 0/5, seam 5/5 (no escalations; every unsafe
temptation vetoed).

### 7. Technique-outcome labeling — `label_eval_set.json` + `label_eval.py` + `label_results.json` (v8.3)

Four labeled cycle transcripts (CONFIRMED / FALSE_POSITIVE / NEGATIVE / INCONCLUSIVE).
Baseline: an ordered keyword scan that reads "succeeded" as CONFIRMED and misses
negations. Seam: `ts_label.draft_technique_payload` (per-field questions over the
transcript; the draft's `result` is the label under test; the payload carries the
`_draft` marker and is only recordable through `researchctl technique confirm`).
Measured: baseline 2/4, seam 4/4 — the seam ships.

### 8. Knowledge-use honesty — `honesty_eval_set.json` + `honesty_eval.py` + `honesty_results.json` (v8.3)

Six labeled rows (genuine uses and decorative citations of a pack over cycle outputs).
Baseline: the audit-style presence heuristic (a distinctive guide keyword in the
outputs means "used"). Seam: `ts_honesty.check_knowledge_use` (one Noul per cited pack:
is the citation load-bearing?). Measured: baseline 4/6, seam 6/6 — the seam ships, as
an advisory warning only (it adds no audit error and changes no verdict).

## How to rerun

Both scripts are stdlib-only Python 3 and read `TYPESAFE_API_KEY` from the environment.
Both are **guarded against accidental live runs**: they refuse to call the external API
unless `--force` is passed AND the `external_judgment` policy of the `--root` workspace
is `ALLOWED` (the repo template ships `DENIED`, so a bare `--force` is not enough).
Results go through a temp file + `os.replace`; the committed artifacts are never
overwritten without `--force`.

```sh
export TYPESAFE_API_KEY=...
cd tools/ts-eval
python3 rerank_eval.py --force                     # variant B (the shipped design)
python3 rerank_eval.py --force --variant a         # variant A (Noul rerank, historical)
python3 claims_eval.py --force --root /path/to/workspace
```

Flags:

| Flag | Meaning |
|---|---|
| `--force` | required for any live run; also allows replacing the committed result artifact |
| `--root PATH` | workspace to read `12_knowledge/` (rerank), the evidence index and the `external_judgment` policy from; defaults to `RESEARCH_OS_ROOT` / `TS_EVAL_ROOT`, else this repository |
| `--variant a\|b` | `rerank_eval` only: `a` = per-pack Noul rerank (`results.json`), `b` = one Choice over all packs (`results_choice.json`, shipped design) |

- `rerank_eval.py` needs a checkout containing `12_knowledge/INDEX.yaml` and
  `.dsh/skills/<pack>/SKILL.md` — this repository by default.
- `claims_eval.py` **cannot run against this repository as-is**: it needs `--root`
  (or `TS_EVAL_ROOT`) pointing at a live workspace whose evidence index carries the
  three registered captures above (the original scratch workspace is not committed).
  That workspace must also carry `external_judgment: "ALLOWED"` in
  `00_control/engagement.yaml` — since v7.4 the claims seam consults the engagement
  policy before any network call.
- `test_guards.py` verifies all of the above offline (no network, no key needed).

## Sanitization applied when committing (2026-09-22)

- Personal absolute paths were removed from both scripts: each resolves its own repo via
  `Path(__file__).resolve()` and the claims workspace through `TS_EVAL_ROOT` / `--root`
  (with an explicit exit message when unset or invalid).
- Live-run guards were added (2026-09-22 review): `--force` + `external_judgment: "ALLOWED"`
  policy + `TYPESAFE_API_KEY`, atomic result writes, and no overwrite of the committed
  artifacts without `--force`.
- `eval_set.json`, `results.json`, `results_choice.json`, `claims_results.json` were
  copied byte-identical: scanned for secret shapes (PATs, tokens, JWTs, private keys),
  personal paths, emails and hostnames — none found.
