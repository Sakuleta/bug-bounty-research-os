# Research Contract

This file is the hard boundary for the engagement.

## Authorization

Only assets, identities, objects, workflows and actions explicitly authorized by the live program policy may be tested.

Never infer authorization from:

- company ownership
- DNS relationships
- certificates
- redirects
- shared infrastructure
- source references
- naming conventions

## Data boundary

Use researcher-controlled accounts, wallets, objects and files whenever possible.
Unexpected third-party data is a stop condition:

```text
STOP → MINIMIZE ACCESS → DO NOT ENUMERATE → PRESERVE MINIMAL EVIDENCE → NOTIFY HUMAN
```

## Safety

Do not perform disruptive scanning, denial of service, credential attacks, indiscriminate fuzzing, destructive mass changes, or any activity prohibited by the program.

Any state-changing research must be reversible by design and verified by read-back.

## External systems

Never send engagement credentials, bounty headers, private identifiers or research metadata to third parties unless the engagement explicitly authorizes that interaction.

## Human-only decisions

OTP/MFA values, credentials held only by the researcher, scope ambiguity, submissions, disclosure and material decisions remain human-gated.

## Evidence standard

Every important claim must be traceable to an observation, source or researcher input.
Never turn an inference into a fact by repetition.
