# Method Self-Attack

After each engagement (or major cycle): attack the method, not just the target. New techniques hide in the branches we closed early and the negatives we trusted too fast.

```text
TARGET -> RESEARCH -> WHAT DID OUR METHOD MISS?
  -> METHOD ATTACK -> NEW TECHNIQUE -> RE-RUN COVERAGE
```

## Protocol

1. TARGET: freeze scope, stack fingerprint, and cycle outcomes as the baseline.
2. RESEARCH: pull one fresh source since engagement start (watchtower CHECK step).
3. WHAT DID OUR METHOD MISS: run the six prompts below against closed branches and trusted negatives.
4. METHOD ATTACK: convert each surviving suspicion into a hypothesis with oracle + negative control.
5. NEW TECHNIQUE: file it via the engine (`17_`) and validate via the checklist (`12_knowledge/novelty-research.md`).
6. RE-RUN COVERAGE: re-execute affected branches only; record delta in `10_learning/`. Stop when all six prompts return written negative answers.

## Six method-attack prompts

1. What did we assume secure? List every component trusted without evidence (CDN, internal API, signed token, agent tool). For each: what single observation would break the trust?
2. Which negative was WEAK? Re-open every FALSE_POSITIVE/NOT_APPLICABLE whose control lacked a clean near-identical run. Re-run the strongest two with a stricter oracle.
3. Which branch closed early? List branches closed on denial, timeout, or rate limit rather than oracle failure. Replay one with slower timing and alternate encoding.
4. Which collision did we skip? Revisit boundary pairs fingerprinted but never tested (proxy/backend, cache/auth, serialize/parse, browser/server). Name X vs Y for each.
5. Which version changed mid-engagement? Diff pinned versions in `freshness.yaml` against current fingerprints; any drift re-opens mapped primitives.
6. Which tool failure did we misread as target behavior? List every timeout, empty response, and parser error logged as "target denied"; reproduce one raw to confirm the attribution.

## Coverage matrix

| Prompt | Branches re-opened | Re-run result | New hypothesis? |
|---|---|---|---|
| assumed-secure | <ids or none> | <confirmed still-clean / flipped> | <ID or dash> |
| weak-negative | <ids> | <result> | <ID or dash> |
| early-close | <ids> | <result> | <ID or dash> |
| skipped-collision | <pairs> | <result> | <ID or dash> |
| version-drift | <components> | <result> | <ID or dash> |
| tool-misread | <events> | <result> | <ID or dash> |

One row per prompt, no blanks. "None" with a one-line reason counts as answered.

## Coverage ledger (deterministic units + critic wave)

The six rows are the shape; the coverage ledger is the completeness mechanism. The
control plane derives the units the ledger can prove — one per FALSE_POSITIVE /
NOT_APPLICABLE hypothesis (weak-negative), one per cycle that entered BLOCKED
(early-close), one per freshness component (assumed-secure), one per stale/unpinned
component (version-drift) — and the critic checks that each unit's subject is named in
its row. `researchctl audit-record method-self-attack` records the derived units and
the unnamed ones on the audit event; `tools/audit.py` warns (never errors) when a row
leaves a unit unnamed, so a bare "none" cannot hide a branch. Rows the ledger cannot
derive units for (skipped-collision, tool-misread) say so in the report instead of
pretending completeness. The critic wave is the re-run loop: answer the unnamed units,
re-record the matrix, repeat until the report is complete. The enforcement below stays
the six-row form check — the coverage ledger is the critic, not a closure gate.

## Worked mini-loop

Baseline: 12 branches closed, 8 NOT_APPLICABLE, 3 FALSE_POSITIVE, 1 VERIFIED. Prompt 2 re-opens the 3 FALSE_POSITIVEs; one lacked a fresh-connection control — re-run flips it to VERIFIED (H-15). Prompt 4 finds cache/auth fingerprinted but untested — new hypothesis H-16, re-run confirms clean with control. Matrix records both; learning log notes "prompt 2 -> H-15 verified; prompt 4 -> H-16 clean".

## Stop rule

Done when all six rows are filled and every flipped result has a hypothesis ID or a corrected learning entry. Budget: one pass per engagement, time-boxed to the cheapest re-runs first. New techniques found here re-enter the normal pipeline — they still need target-specific impact plus a negative control before they count.

Enforcement: this is a required closure audit class (`07_AUDIT_CLOSURE.md` #10).
Record it as `researchctl audit-record method-self-attack PASS "<summary>" --matrix matrix.json --evidence <E-id>` — the control plane refuses a missing or blank matrix row, and `tools/audit.py` re-checks the event. Prose cannot skip it: no current PASS, no closure.

Close-out line (required in learning log): which prompt produced a re-run, and what did it change. "No misses found" is allowed only with all six answers written.

New techniques discovered here are filed as ordinary hypotheses and counted in the next cycle plan — the self-attack earns its keep only when re-runs change coverage.
