# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)

# Last Result

- technique: T-000001 (http-edge-differential)
- result: INCONCLUSIVE
- cycle: C-0001
- time: 2026-09-21T17:51:10Z
- interpretation: Single GET only; cache-key behavior of raw vs normalized paths was not exercised.
- learning: For edge cache questions the executor must send the variant pair before any claim; one baseline request is not a negative.
- evidence: E-000001
