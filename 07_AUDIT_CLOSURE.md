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
matrix and `tools/audit.py` re-checks the event.

## Closure requirements

Create `06_audits/CLOSURE-PROOF.md` only when all required audit classes have current `AUDIT_RECORDED` PASS events. The YAML closure-readiness file is only a projection for inspection.

The closure proof must contain:

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

## Closure decision

Close only when there is no unresolved high-value legal next step under the current authorization boundary.
“Nothing found yet” is not a closure condition.

## Machine-checkable closure inputs

The closure proof should be generated only after the control plane audit confirms:

- event IDs are contiguous and parseable;
- lifecycle transitions obey the state machines;
- every cited E-* reference resolves to a registered artifact whose hash still matches;
- pending human gates are resolved or explicitly dispositioned;
- no forbidden direct lifecycle edits are detected;
- required freshness and cleanup ledgers exist.

## Required current audit events

Record PASS through the control plane for: `scope`, `coverage`, `negative`, `open-hypothesis`, `novelty-duplicate`, and `hygiene-cleanup`. A later material research event makes earlier declarations stale; closure must re-run them.
