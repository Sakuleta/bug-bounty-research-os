# GENERATED — do not edit by hand; rebuilt by the control plane on every mutation (tools/build_context.py)

# Current Context


## ENGAGEMENT POLICY

program:
  name: "Shadow rehearsal (example.com)"
  platform: "DIRECT"
  url: "https://example.com"
  policy_source: "IANA example domain — reserved for documentation; harmless GETs only"
  policy_retrieved_at: "2026-09-21"

researcher:
  public_handle: "NONE"
  identity_reference: "local shadow run"
  profile: "00_control/researcher-profile.yaml"

scope:
  assets:
  - "example.com"
  out_of_scope: []
  allowed_functionality: ["read-only GET"]
  prohibited_functionality: ["any state-changing request"]
  asset_specific_rules: []

accounts:
  researcher_controlled: []
  roles_available: []
  account_creation_rules: "none — no accounts created"
  data_ownership_rules: "researcher-owned only"

traffic:
  required_headers: []
  rate_limits: "one request per action; no automation beyond the controlled executor"
  auth_traffic_policy: "anonymous only"
  automation_policy: "controlled executor only"

reporting:
  rules: "shadow run — nothing to report"
  severity_method: "n/a"
  disclosure: "n/a"
  human_approval_required: true

environment:
  workspace_path: "/Users/mardinli/Desktop/shadow-engagement"
  browser_profile: "none"
  network_context: "researcher workstation"

confidence: "VERIFIED"

## RUN STATUS

engagement_status: "CLOSED"
current_cycle: null
last_state_update: "2026-09-21T17:51:13Z"
last_audit: "2026-09-21T17:51:13Z"
open_high_value_hypotheses: "0"
open_unknowns: "0"
pending_human_gate: false
lab_ready: false

## FRESHNESS

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
components: [{"action": "pinned today; two-week cadence noted", "last_checked": "2026-09-21", "new_primitives": [], "pinned_version": "v153", "sources": ["release-feed"], "target_component": "chrome"}, {"action": "no new primitives", "last_checked": "2026-09-21", "new_primitives": [], "pinned_version": "observed 2026-09-21", "sources": ["executor capture headers"], "target_component": "example.com edge (Cloudflare)"}]

## KNOWLEDGE_SELECTION

auto-selected packs (relevance-ranked, cap 4): none — confirm or override in the cycle knowledge_triage

## ACTIVE CYCLE

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
cycle_id: null

## LAST RESULT

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)

# Last Result

- technique: T-000001 (http-edge-differential)
- result: INCONCLUSIVE
- cycle: C-0001
- time: 2026-09-21T17:51:10Z
- interpretation: Single GET only; cache-key behavior of raw vs normalized paths was not exercised.
- learning: For edge cache questions the executor must send the variant pair before any claim; one baseline request is not a negative.
- evidence: E-000001

## UNKNOWN / ASSUMPTION LEDGERS

# Persistent unknowns. Every material unknown gets a terminal state.
unknowns: []

# Assumptions that could change a security conclusion.
assumptions: []


## TOOL / LAB

# Tool registry
tools:
  - name: adb
    state: "MISSING"
    purpose: "Android SDK platform-tools"
    detail: ""
  - name: emulator
    state: "MISSING"
    purpose: "Android Emulator"
    detail: ""
  - name: docker
    state: "READY"
    purpose: "Docker"
    detail: "Docker version 29.4.0, build 9d7ad9f"
  - name: node
    state: "READY"
    purpose: "Node.js"
    detail: "v25.9.0"
  - name: python3
    state: "READY"
    purpose: "Python 3"
    detail: "Python 3.14.6"
  - name: nuclei
    state: "MISSING"
    purpose: "ProjectDiscovery nuclei"
    detail: ""
  - name: ffuf
    state: "MISSING"
    purpose: "ffuf"
    detail: ""
  - name: mitmproxy
    state: "MISSING"
    purpose: "mitmproxy"
    detail: ""
  - name: jadx
    state: "READY"
    purpose: "jadx"
    detail: "1.5.6"
  - name: frida
    state: "MISSING"
    purpose: "Frida tools"
    detail: ""
  - name: ios-simulator
    state: "FAILED"
    purpose: "Xcode simulator (macOS only)"
    detail: "xcrun: error: sh -c '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Dev"

status: FAILED
provisioner: tools/provision.py
isolated_lab: lab/
installation_policy: ai-runtime-managed
auto_exploit: false

