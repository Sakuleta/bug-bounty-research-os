# Program Learning

Maintain a program-specific knowledge file in `10_learning/PROGRAM-KNOWLEDGE.md`.

Record only verified or clearly attributed facts.

Recommended sections:

```text
ARCHITECTURE
AUTH MODEL
PROGRAM RULES
KNOWN EXCLUSIONS
DISCLOSED PATTERNS
TRIAGE CALIBRATION
DUPLICATE SIGNALS
RATE / EDGE BEHAVIOR
HIGH-VALUE SURFACES
TESTED SURFACES
OPEN UNKNOWNs
RESEARCHER LESSONS
```

A closure, duplicate or severity decision is useful data only after its source and context are preserved.

Technique outcomes are events, not hand-written notes: record them with `researchctl technique evaluate`. `10_learning/technique-discoveries.md` and `11_runtime/last-result.md` are projections of those events; this file stays curated program-level knowledge (verified or clearly attributed facts, with source and context preserved).

Promotion back into the pack library is reviewed, never silent: `researchctl knowledge
propose` redacts the title and body, records the proposal (pack, title, body, optional
`technique_ref`/`evidence_refs`, optional `recheck_date`) with the artifact's sha256 and
a digest of every INDEX-declared pack file, and writes it under the protected
`10_learning/knowledge-proposals/`. `researchctl knowledge resolve <KP-id>
APPLIED|REJECTED --reference <human ref> [--gate G-xxxx]` closes it — APPLIED recomputes
the pack digests and requires real CONTENT to differ (a timestamp touch is refused;
missing files are errors), so provenance and the recheck date survive the edit, and
`--reference` is recorded friction while `--gate` binds the resolution to a RESOLVED
human gate when one is named. `10_learning/knowledge-proposals.yaml` is the status
projection (audited against the artifacts), and `10_learning/knowledge-usage.yaml` shows
which packs were used, skipped or cited, with the audit warning about packs not
considered in the last 10 cycles.

