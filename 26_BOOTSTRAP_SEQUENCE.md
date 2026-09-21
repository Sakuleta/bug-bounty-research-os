# Bootstrap Sequence

Bootstrap is an active setup phase, not a passive checklist.

```text
1. Create engagement folder and initialize `10_learning/` + `11_runtime/` ledgers.
2. Populate policy and scope from authoritative source.
3. Load `00_control/identity-binding.yaml` and verify the expected identity/session context without storing secrets.
4. Inventory all available tools / MCP / web / browser / system capabilities (`python3 tools/provision.py <ROOT> --check-only`; record in `11_runtime/tool-registry.yaml`).
5. Select the safest and strongest capability for each expected surface.
6. Verify isolated filesystem / process / browser context.
7. Provision ordinary local research dependencies when required (`python3 tools/provision.py <ROOT>`; status in `11_runtime/lab-status.yaml`).
8. Provision mobile emulator / simulator when mobile is in scope.
9. Obtain authorized client artifacts when required.
10. Verify artifact identity / version / hash.
11. Configure network observation and evidence capture.
12. Establish traffic and safety constraints.
13. Build initial asset inventory and record it in `02_surface/endpoints.yaml` — the
    endpoint ledger `tools/audit.py` requires once research has started (one entry per
    observed endpoint; `endpoints: []` only until discovery fills it).
14. Perform low-risk surface discovery.
15. Fingerprint applications and protocols.
16. Build host/application/endpoint/object graphs.
17. Identify trust boundaries and state transitions.
18. Seed the hypothesis portfolio.
19. Run the deterministic audit (`python3 tools/audit.py <ROOT>`).
20. Start cycle C-0001 through the control plane.
```

## Tool-first rule

Do not stop because the environment is not preconfigured.
First determine whether the missing capability can be safely provisioned by the agent.

## Mobile bootstrap

If mobile is in scope, bootstrap should normally reach:

```text
EMULATOR / SIMULATOR READY
APP INSTALLED
NETWORK OBSERVATION READY
PACKAGE ID VERIFIED
BASIC FLOW DISCOVERED
```

before declaring mobile research blocked.

If a human factor is required, ask only for that factor and resume.

Never start with exploitation or a generic scanner report.
