# Audit & Closure

## Audit classes

### 1. Scope audit
Every tested asset is demonstrably in scope.

### 2. State audit
Canonical state is internally consistent and event history explains material transitions.

### 3. Coverage audit
Every applicable matrix cell has a terminal state or a named blocker.

### 4. Negative audit
Important negative conclusions have validated controls.

### 5. Novelty audit
A candidate is compared against program history and current public research.

### 6. Duplicate audit
Root cause, primitive, representation, direction and impact are compared.

### 7. Tool limitation audit
Tool failure is never mislabeled as target behavior.

### 8. Hygiene audit
No credentials, secrets, unrelated PII or personal-environment artifacts remain in reportable material.

### 9. Open-hypothesis audit
No high-value legal hypothesis is left without an explicit disposition.

### 10. Method self-attack audit
The method attacks itself before closure (`33_METHOD_SELF_ATTACK.md`): all six prompts
(assumed-secure, weak-negative, early-close, skipped-collision, version-drift,
tool-misread) answered as a six-row matrix, no blanks — "none — reason" counts as
answered. Machine-checked: `researchctl audit-record method-self-attack PASS "<summary>"
--matrix matrix.json --evidence <E-id>`; the control plane refuses a missing or blank
matrix and `tools/audit.py` re-checks the event. The control plane also derives coverage
units from the ledger (weak-negative hypotheses, BLOCKED cycles, freshness components)
and records what the matrix left unnamed on the event; the audit warns on unnamed units —
the completeness critic, never a closure gate.

## Closure proof (machine-checked)

`06_audits/CLOSURE-PROOF.md` is not a free-text report: `tools/audit.py --closure`
parses it and fails on a missing file, a malformed section, or an unanswered judgment.
`06_audits/closure-readiness.yaml` remains only a projection for inspection.

The proof must contain all 17 `##` sections **exactly once** (a repeated required
heading is a `duplicate section` error):

```text
SCOPE_PROOF
SURFACE_COVERAGE
AUTHORIZATION_COVERAGE
WORKFLOW_COVERAGE
TECHNIQUE_COVERAGE
NEGATIVE_EVIDENCE
VERIFIED_FINDINGS
FALSE_POSITIVES
BLOCKERS
NOVELTY_CHECK
DUPLICATE_CHECK
STATE_INTEGRITY
TOOL_LIMITATIONS
HYGIENE
CLEANUP
REMAINING_UNKNOWNS
FINAL_OPEN-HYPOTHESIS_AUDIT
```

Body rule (machine-checked, so a placeholder cannot pass as judgment):

- no `todo(human)` marker however it is cased or spaced — the audit matches
  `todo\s*\(\s*human\s*\)` case-insensitively;
- after removing whitespace and zero-width/invisible characters
  (`[\s\u200b-\u200f\u2060\ufeff]`), at least 20 characters remain;
- the body carries at least one letter, or at least 3 whitespace-separated word
  tokens where a token counts as a word only when it contains a letter — so
  punctuation-only, digit-only and separator-only bodies fail (`done`, `x`, `.`,
  a bare zero-width character, duplicated skeleton prompts).

Parser rules (spec F2/F3/F7): fenced code blocks (```` ``` ```` toggling) are opaque —
a fenced `## ...` line is never a section heading and a fenced `TODO(human)` never
counts as unanswered; an unlisted `##` subheading is body text for the active section,
never a section terminator (only headings from the required list switch sections).

### Emit flow

1. `python3 tools/audit.py <ROOT> --emit-proof` writes/refreshes the proof. It is
   deterministic: the mechanical sections are filled from the ledger and projections
   (`SCOPE_PROOF` gate mode + assets, `TECHNIQUE_COVERAGE` technique results,
   `VERIFIED_FINDINGS` hypothesis ids + status, `STATE_INTEGRITY` cycle ids + status +
   every latest audit class as `class: STATUS (EV-N...)`, `HYGIENE` evidence ids + kind),
   and every judgment section (coverage, novelty, blockers, cleanup, …) carries a
   `TODO(human): <prompt>` line. An audit fact recorded before the latest material
   (non-audit) event is marked `(EV-N...; stale — re-record)`, mirroring the
   closure-currentness rule, so a stale PASS is never emitted as if it still held.
2. Fill every judgment prompt with engagement-specific reasoning, citing ids. Mechanical
   facts are derived, not hand-typed; if the ledger moved, re-run the audit first.
3. `python3 tools/audit.py <ROOT> --closure` must pass before closure.
4. `--emit-proof` refuses to overwrite a filled proof (no `TODO(human)` left in the
   sections); pass `--force` to regenerate the skeleton and discard the prose.

## Audit content rules

Every `AUDIT_RECORDED` event is checked for content, not just status:

- at least one `evidence_ref`;
- a summary of ≥ 20 characters and ≥ 3 words after stripping.

Named-entity lite:

- `scope` summary names at least one current asset, or says `gate: none` / `no assets`;
- `coverage` summary names at least one `C-NNNN`, or says `no cycles`;
- `open-hypothesis` summary names at least one `H-NNNN`, or says `none`.

`researchctl audit-record` enforces the summary rule at write time; the audit grades
violations on versioned events as errors and on legacy events (no `os_version`, pre-7.3)
as warnings.

## Review binding

A cycle that reached `REVIEWED` must carry, per axis, a review packet with `verdict`
`pass`, an explicit `reviewer`, a distinct `run_id`, and non-empty `evidence_quotes`.
Every quote must be a substring (≥ 20 stripped characters) of the content-addressed
store copy of the referenced evidence — never the living file. Versioned packets are
held to the rule as errors; legacy packets warn.

The verifier instructions are procedural and live in `.dsh/skills/fresh-verifier/SKILL.md`
(adapted from Cloudflare's security-audit skill, not imported): refute-don't-confirm
(a `pass` means the refutation attempt failed, with the attempts recorded),
fingerprint stability (record the packet digest and the evidence store digests with the
verdict; a packet that moved materially invalidates the review), and
material-replacement re-verification (a replaced claim, quote or artifact invalidates
any earlier pass — re-verify from the fresh packet). Live-target validation on
authorized targets routes through `researchctl prepare` + the controlled executors;
`needs_validation`/`BLOCKED` is only for genuine authorization or capability blockers,
with the blocker named. The binding rules above stay enforced by the control plane and
the audit; the prompt blocks change how reviewers work, not what the guards accept.

## Closure decision

Close only when there is no unresolved high-value legal next step under the current authorization boundary.
“Nothing found yet” is not a closure condition.

## Machine-checkable closure inputs

The closure proof should be generated only after the control plane audit confirms:

- event IDs are contiguous and parseable;
- lifecycle transitions obey the state machines (cycle `VERIFIED` from archived ledgers
  is normalized to `REVIEWED` on read);
- every cited E-* reference resolves to a registered artifact whose hash still matches;
- pending human gates are resolved or explicitly dispositioned;
- the closure proof binds a resolved APPROVED closure-review gate (id + reference);
- a recorded current PASS agrees with the freshly re-derived class result;
- no forbidden direct lifecycle edits are detected;
- required freshness and cleanup ledgers exist;
- versioned actions carry their consumed preflight `token_nonce`.

## Required current audit events

Record PASS through the control plane for all seven classes: `scope`, `coverage`,
`negative`, `open-hypothesis`, `novelty-duplicate`, `hygiene-cleanup`, and
`method-self-attack`. A later material research event makes earlier declarations stale;
closure must re-run them.

## Closure-review gate attestation

Prose cannot close: `06_audits/CLOSURE-PROOF.md` must bind a resolved human gate
(`Closure-Gate: G-xxxx (reference: <human ticket>)`), and the ledger must hold the
matching `HUMAN_GATE_RESOLVED` event with decision `APPROVED` and the same reference.
Request the gate while a cycle runs (`researchctl gate request` with `what_is_needed`
naming the closure review); `--closure` refuses a proof with no binding, an unknown
gate, a non-APPROVED resolution, or a reference mismatch, however polished the
sections are. Twenty characters of filler pass the section form check by design — the
gate is what makes the proof load-bearing.

## Fresh-result contradiction

`--closure` re-derives each machine-verifiable class result from freshly performed
checks and fails when a recorded current PASS contradicts them (`closure
contradiction: <class> ...`): scope, coverage, hygiene-cleanup and method-self-attack
contradict on their fresh error domains; negative contradicts when a CLOSED cycle has
no `TECHNIQUE_EVALUATED`; open-hypothesis contradicts when an open hypothesis is
neither named nor closed out by the latest open-hypothesis audit; novelty-duplicate
contradicts when a VERIFIED hypothesis is named nowhere in the latest
novelty-duplicate summary (each finding must visibly pass the program-history and
current-research comparison). The remaining judgment content is backed by the
closure-review gate attestation above. The ledger hash chain stays unkeyed (`15_TOOLING.md` known limits) — it proves
accidental corruption and lazy tampering, not authorship; the gate reference (a human
ticket) is the out-of-band trail, not a cryptographic proof.
