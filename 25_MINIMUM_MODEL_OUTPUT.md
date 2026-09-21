# Minimum Model Output

Every controller cycle ends with a compact state update.

```yaml
cycle_id: "C-0001"
question: "<QUESTION>"
status: "VERIFIED|FALSE_POSITIVE|BLOCKED|NOT_APPLICABLE|NEEDS_PIVOT"
observations: []
interpretation: "<INTERPRETATION>"
confidence: "LOW|MEDIUM|HIGH"
evidence_refs: []
state_changes: []
new_hypotheses: []
open_unknowns: []
next_question: "<NEXT>"
human_gate_required: false
```

Long narrative notes can coexist with this summary; the summary exists to make the next context deterministic.
