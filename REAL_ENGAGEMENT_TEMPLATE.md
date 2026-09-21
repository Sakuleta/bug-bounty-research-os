# Recommended New Bug Bounty Engagement

Copy this OS directory once per engagement and use the copied directory as the engagement workspace.

Then populate:

```text
<program-workspace>/
├── 00_control/
│   ├── engagement.yaml
│   ├── policy.md
│   ├── research-contract.md
│   └── identity-reference.md
│
├── 01_intelligence/
│   ├── recon/
│   ├── architecture/
│   ├── client/
│   └── program-knowledge.md
│
├── 02_surface/
│   ├── hosts.yaml
│   ├── endpoints.yaml
│   ├── objects.yaml
│   ├── workflows.yaml
│   └── trust-boundaries.yaml
│
├── 03_hypotheses/
│   ├── active/
│   └── archive/
│
├── 04_cycles/
│   ├── C-0001/
│   │   ├── objective.md
│   │   ├── plan.yaml
│   │   └── results.md
│   └── ...
│
├── 05_findings/
│   └── F-0001/
│       ├── hypothesis.md
│       ├── validation.md
│       ├── report-draft.md
│       └── proof/
│
├── 06_audits/
│   ├── audit-log.yaml
│   ├── closure-readiness.yaml
│   ├── negative-audit.md
│   ├── novelty-audit.md
│   └── CLOSURE-PROOF.md
│
├── 07_reports/
│   ├── ready/
│   ├── submitted/
│   └── closed/
│
├── 08_artifacts/
│   ├── raw/
│   ├── sanitized/
│   └── screenshots/
│
├── 09_workers/
│   ├── inbox/
│   ├── outbox/
│   └── archive/
│
├── 10_learning/
│   ├── PROGRAM-KNOWLEDGE.md
│   ├── unknowns.yaml
│   ├── assumptions.yaml
│   ├── corrections.md
│   └── technique-discoveries.md
│
└── 11_runtime/
    ├── current-context.md
    ├── active-cycle.yaml
    ├── run-status.yaml
    ├── last-result.md
    ├── events.jsonl
    ├── evidence-index.jsonl
    ├── human-gates/
    └── tool-registry.yaml
```

## The six files the controller should care about most

```text
00_control/engagement.yaml
00_control/research-contract.md
00_control/identity-binding.yaml
11_runtime/current-context.md
11_runtime/active-cycle.yaml
11_runtime/run-status.yaml
```

Everything else is pulled when it becomes relevant.
