# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)

# Technique Discoveries

One entry per TECHNIQUE_EVALUATED event, reconstructed from `11_runtime/events.jsonl`.

## T-000001 — http-edge-differential → INCONCLUSIVE
- time: 2026-09-21T17:51:10Z
- cycle: C-0001
- interpretation: Single GET only; cache-key behavior of raw vs normalized paths was not exercised.
- learning: For edge cache questions the executor must send the variant pair before any claim; one baseline request is not a negative.
- evidence: E-000001

