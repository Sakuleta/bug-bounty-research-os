---
name: parsers-injection
description: "Parser and interpreter boundaries — SQL/NoSQL, SSTI, XXE, deserialization, prototype pollution, Unicode and canonicalization gaps, archive traversal, header and SMTP injection."
---

# Parser / Injection Research

The canonical question: two components interpret the same value with different rules, and **does the difference change a security decision?** Attacker bytes surviving to a dangerous interpreter is the primitive; the decision change is the bug.

## Run this

1. **Detect before exploiting** — one polyglot or error probe per interpreter class, classified (reflected text vs evaluated vs error) before any escalation. Done when each interpreter in play has a fingerprint.
2. **Prefer boolean and error oracles over enumeration** — SQL: `AND 1=1` vs `AND 1=2` divergence, or one short `SLEEP` with interleaved benign controls; enumerate only to the minimum (column count) that demonstrates injectability.
3. **Prove reads on canaries** — XXE via collaborator callback or `php://filter` read of a researcher-planted canary file; deserialization via magic-bytes/reflection change or collaborator callback. Canary paths and your own sessions only; production secrets stay out of the proof.
4. **Pollute only your own session objects** — `__proto__[bbcanary]` observable in a fresh object plus a gadget consuming it; shared prototypes and stored templates stay untouched.
5. **Write toward canary paths only** — an archive `../` entry or symlink that lands a canary filename outside the destination inside a researcher-owned workspace; system paths stay out.
6. **Compare normalization orders** — the same value before and after NFC/NFKC, case folding, slash and dot-segment normalization, with the post-normalization form reaching the sink.

## Done when

- Every interpreter class tested has a recorded classification and, where live, one minimal confirmation beside a control.
- Each exploited primitive has a canary-based proof and a hardened-parser negative.
- The normalization order of every tested boundary is named (canonicalize-then-check vs check-then-canonicalize).

## Stop conditions

Backend errors spike; WAF blocks engage; a state-changing evaluation occurs (email sent, file written, command executed); pooled-parser behavior suggests shared-infrastructure impact. Halt and report the oracle.

## Depth

Field guide: `12_knowledge/parsers-injection/parsers.md` — families, oracle catalog, false positives, template-engine and database version notes.
