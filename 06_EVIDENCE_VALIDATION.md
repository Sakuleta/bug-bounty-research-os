# Evidence & Validation

## Evidence hierarchy

```text
RAW OBSERVATION
→ REPRODUCED OBSERVATION
→ MINIMAL PROOF
→ SECURITY-BOUNDARY PROOF
→ IMPACT PROOF
→ REPORT-READY EVIDENCE
```

## Every positive needs

- clean baseline
- researcher-controlled state
- exact target
- exact request/action
- exact observed response/result
- before/after state where relevant
- security boundary identified
- reproducible proof
- cleanup

## Every negative needs

A negative is not equivalent to “nothing happened”.

Use:

```text
NEGATIVE_UNPROVEN
NEGATIVE_WEAK
NEGATIVE_VALIDATED
NEGATIVE_HIGH_CONFIDENCE
```

A negative can only become strong when:

- preconditions are proven,
- the instrument can detect a positive control,
- the relevant representation was tested,
- the relevant state was tested,
- the relevant direction was tested,
- and important alternate implementations were considered.

## Read-back rule

Never infer state change from a status code alone.
Whenever safe, verify the post-condition by reading the resulting state.

## Surprising results

Before blaming the target, test:

1. harness error,
2. malformed request,
3. wrong session/state,
4. wrong parser or oracle,
5. self-generated traffic effects,
6. only then genuine target behavior.

## Evidence references

Use stable IDs:

```text
E-000001
E-000002
...
```

Do not put secrets in evidence names or filenames.

## Registered evidence

Evidence that is cited by a lifecycle transition should be registered with the control plane. Registration captures:

```text
E-ID + engagement-relative path + SHA-256 + kind + source + cycle
```

A path string alone is not evidence identity.
