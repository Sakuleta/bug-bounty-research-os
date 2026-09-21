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

## Submission gate

The reporting platform/form is itself a live source of current constraints. Read it immediately before submission and verify the newest validation/check output.

## Platform notes (HackerOne / Bugcrowd / Intigriti)

- Submit only through the program's own platform channel (H1 report, Bugcrowd submission, Intigriti report) and only after the human gate approves. Never auto-submit via API, email, or any side channel.
- Scope, duplicates, and severity follow the platform's live program page at submission time, not a cached copy. Re-check bounty table, out-of-scope list, and disclosure terms in the same session as submission.
- Researcher identity comes from `00_control/researcher-profile.yaml` (public handles only); production credentials are never stored in the workspace and are human-gated per `08_human_gates.md`. The sole exception is researcher-authorized local-only throwaway credentials under `lab/credentials/` (0600, never evidence) per `29_SECURITY_HYGIENE.md`.
- Hacktivity/public disclosures are research sources only (`12_knowledge/novelty-research.md` step 6); never copy another report's content into a submission.
