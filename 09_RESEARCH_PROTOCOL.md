# Research Protocol

## Current research loop

When a class or platform is unfamiliar or may have changed recently:

```text
TARGET FACTS
→ TECHNOLOGY / VERSION
→ PRIMARY SOURCES
→ CURRENT SECURITY RESEARCH
→ PRIMITIVES / FAILURE MODES
→ TARGET-RELEVANCE TEST
→ HYPOTHESES
```

## Source classes

Prefer current:

- official vendor advisories
- framework security notes
- relevant standards
- established security research
- reputable technical writeups
- program disclosures where available

External material informs hypotheses; it does not grant authorization.

## Research note

Each current-research note stores:

```yaml
source: "<SOURCE>"
retrieved_at: "<TIMESTAMP>"
technology: "<TECHNOLOGY>"
claim: "<WHAT THE SOURCE SHOWS>"
preconditions: []
black_box_indicators: []
false_positive_traps: []
target_relevance: "<WHY_THIS_TARGET>"
hypotheses_created: []
```

## Novelty engine

Do not only ask “what known bug applies here?”
Ask:

- Where do two components parse the same input differently?
- Where is a state signed, cached, serialized, normalized or reinterpreted?
- Where does identity cross a protocol boundary?
- Where does a browser disagree with the server?
- Where does one service trust data produced by another?
- Where does an authorization decision happen earlier than the final state mutation?
- Which secure control was tested only in one representation?

## Stop rule

Research the current class only until it changes the hypothesis space. Do not turn reading into an endless literature review.
