# Report Protocol

## Finding lifecycle

```text
OBSERVATION
→ HYPOTHESIS
→ VERIFIED
→ REPORT-DRAFT
→ HUMAN REVIEW
→ SUBMITTED (only if authorized)
→ TRIAGED
→ LEARNING
```

## Finding record (machine-enforced)

The lifecycle above is not honor-system past VERIFIED. Every VERIFIED hypothesis `H-NNNN`
must own `05_findings/F-H-NNNN/` containing at minimum:

```text
05_findings/F-H-NNNN/
├── hypothesis.md    # claim + ledger links (creation/transition event IDs)
├── validation.md    # positive controls, falsification attempts, duplicates/novelty,
│                    # researcher-vs-target behavior separation, residual risks
└── report-draft.md  # binding to the filing copy in 07_reports/ + submission state
```

`tools/audit.py` FAILs any workspace with a VERIFIED hypothesis lacking this record.
No finding advances to HUMAN REVIEW without `validation.md`; no submission without the
bound draft. Lessons from triage feed back into `10_learning/` (LEARNING stage).

## Report must answer

1. What is wrong?
2. Where is it wrong?
3. What security property is violated?
4. How can a researcher reproduce it?
5. What is the concrete impact?
6. What evidence proves it?
7. What is the minimal safe remediation direction?

## Report quality rules

- concise title
- clear preconditions
- copyable reproduction steps
- expected vs actual behavior
- concrete impact
- redacted evidence
- root cause where supportable
- no unsupported severity inflation
- no unnecessary secrets or personal data

 Researchers should verify scope and duplicates before submission.

## Severity anchors (calibration)

Severity comes from a **boundary defeat**, not from a checklist deviation: a finding
needs the control that should have stopped the request to have failed, reproduced with
a clean near-identical control. Checklist deviations (a missing header on a
non-exploitable path, a scanner template match, a policy difference with no control
failure) are not findings — record them as hardening notes or leave them in the method
self-attack matrix. The discriminator: *state what the attacker gains that the control
should have prevented.* If that sentence cannot be written, the severity rationale is
missing.

```text
critical       boundary defeat with direct cross-tenant/account impact, unauthenticated
               code execution, or full credential compromise; path reproduced end-to-end
high           boundary defeat with limited scope (one object class, read-only data) or a
               reachable chained precondition; clear security impact
medium         real boundary weakening behind an unusual precondition, or low-impact
               disclosure with demonstrated access beyond the intended principal
low            hardening: defense-in-depth gaps, version disclosure, misconfiguration with
               no demonstrated boundary defeat
informational  observations with no security boundary at stake
```

The finding record's `report-draft.md` fills `## Severity Rationale` against these
anchors (the template carries the discriminator prompt). The program's own severity
method (`00_control/engagement.yaml` `severity_method`, surfaced in
`11_runtime/current-context.md`) wins where it is stricter than these anchors.

## Draft claim audit — aid, not a gate

A finding's `report-draft.md` can be audited before human review with
`researchctl claims-draft <root> <draft.md> [--triage]`. It extracts every
sentence carrying a registered-evidence citation (`E-\d{6,}`) — fenced code,
indented code and headings are skipped, table rows count as their own sentences
— and checks each claim against the content-addressed evidence copy (supports /
contradicts / says_nothing, auto-accepted at >= 0.8 confidence, below that
flagged); refs absent from the evidence index are reported as errors, never
crashes. With `--triage` the evidence is split into bounded passages and one
selection question narrows the relation check to the most relevant passage
(`none` -> `says_nothing` with `triage: no relevant passage`, no relation call;
the result records `passage_index`, `triage_confidence` and
`dropped_passages`). The audit honours the engagement's `external_judgment`
policy (DENIED -> `source: unavailable`, the default posture) and is an aid for
the reviewer packets: it exits 0 with flagged verdicts unless `--fail-on-flag`
is passed, and it never gates closure, hypotheses, REVIEWED, submission or
authorization.

## Submission gate

The reporting platform/form is itself a live source of current constraints. Read it immediately before submission and verify the newest validation/check output.

## Platform notes (HackerOne / Bugcrowd / Intigriti)

- Submit only through the program's own platform channel (H1 report, Bugcrowd submission, Intigriti report) and only after the human gate approves. Never auto-submit via API, email, or any side channel. [PROCEDURAL — no tool watches the submission channel.]
- Scope, duplicates, and severity follow the platform's live program page at submission time, not a cached copy. Re-check bounty table, out-of-scope list, and disclosure terms in the same session as submission.
- Researcher identity comes from `00_control/researcher-profile.yaml` (public handles only); production credentials are never stored in the workspace and are human-gated per `08_human_gates.md`. The sole exception is researcher-authorized local-only throwaway credentials under `lab/credentials/` (0600, never evidence) per `29_SECURITY_HYGIENE.md`.
- Hacktivity/public disclosures are research sources only (`12_knowledge/novelty-research.md` step 6); never copy another report's content into a submission.
