# Knowledge Library

These files are loaded by relevance, not all at once.

Single seam: `tools/knowledge_index.py` owns parse + validate + rank + resolve
for `INDEX.yaml`. Tools are thin adapters over it; do not re-parse the index
anywhere else.

A deep knowledge pack uses 7 sections:

1. Research families (when to load)
2. Preconditions (architectural conditions that must hold)
3. Oracles (black-box observables distinguishing vuln vs secure)
4. Minimal safe proof (smallest reversible test + stop conditions)
5. False positives (benign explanations + how to rule out)
6. Version/implementation notes (where behavior differs)
7. References (named sources, no fake URLs)

## Skills layer (DSH)

Each pack also ships a skill at `.dsh/skills/<pack>/SKILL.md` (model-invoked). The skill is
the entry point the agent reaches on its own: trigger-rich description, the operational
ladder, checkable completion criteria, stop conditions — and a pointer back into the pack
file here for depth (oracles, false positives, version notes). The skill carries the
process; this library carries the evidence. Written per `writing-for-agents`
(mattpocock/skills): descriptions are always-loaded pointers, so they front-load the
leading word and list one trigger per branch.

## Usage telemetry

Cycle triage dispositions feed `10_learning/knowledge-usage.yaml`: each
`CYCLE_CREATED`/`CYCLE_UPDATED` `knowledge_triage` entry counts a `use` (verdict USE)
or `skip` (verdict SKIP) for its pack, with the event time as `last_used` and the
cycle id appended to `cycles`. A pack counts at most once per cycle — the latest
triage list for that cycle (CYCLE_UPDATED can rewrite it) and the latest row for a
duplicate pack within it win — and only complete dispositions count (pack a non-empty
string, verdict USE/SKIP, non-empty reason); malformed rows are ignored, never
stringified. `TECHNIQUE_EVALUATED` payloads may cite packs with the optional
`knowledge_packs` list (every name must exist in this index); a pack counts once per
event (set semantics), updates `last_cited`, and the event's cycle lands in
`cited_cycles`. The projection is rebuilt on every mutation like the other views, and
indexed packs with no events stay at zero — `researchctl knowledge usage [--unused]`
renders the counters in JSON plus a human summary, and `--unused` is the all-time
view: packs never seen in any disposition or citation. The machine audit's
never-considered warning (WARNING, bounded to the first 10 names) is windowed to the
last 10 cycles (`not considered in the last 10 cycles`), so a pack used once and then
abandoned surfaces instead of rotting.

## Reviewed promotion path

An engagement learning reaches a pack only through review:

1. `researchctl knowledge propose payload.json` with
   `{pack, title, body, technique_ref?, evidence_refs?, recheck_date?}` — the pack must
   exist here, title and body are redacted before they touch disk (a secret-shaped
   string never enters the artifact) and must be real content, `recheck_date` must be a
   future `YYYY-MM-DD`, `technique_ref` must name a recorded `T-…` evaluation, and
   evidence refs are validated like every other ref list. The proposal lands in
   `10_learning/knowledge-proposals/<KP-id>-<slug>.md` (front matter carries the
   redacted title and provenance) and records `KNOWLEDGE_PROPOSED` with the sha256 of
   the written artifact plus a `pack_digests` snapshot of every INDEX-declared pack
   file. The directory is control-plane-owned: the enforcer denies writes and
   destructive targets under `10_learning/knowledge-proposals/`.
2. A human resolves it: `researchctl knowledge resolve <KP-id> APPLIED|REJECTED
   --reference <human ref> [--gate G-xxxx]`. `APPLIED` recomputes the pack digests and
   requires at least one to differ — a byte-identical file (even after an `utime`/
   touch) is refused, missing/unreadable files are errors, so edit the pack's real
   content first; `REJECTED` needs no edit. `--reference` is the recorded friction, not
   cryptographic proof; passing `--gate` additionally binds the resolution to an
   existing RESOLVED human gate, and without it the resolution is not bound to one.
3. `researchctl knowledge proposals` reads the `10_learning/knowledge-proposals.yaml`
   status projection (latest resolution wins; an unknown decision projects as the
   explicit `INVALID` marker); the machine audit warns when a PROPOSED proposal's
   `recheck_date` has passed and re-validates every recorded proposal artifact against
   its `body_sha256`.

