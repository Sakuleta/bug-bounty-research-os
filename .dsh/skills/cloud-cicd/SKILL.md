---
name: cloud-cicd
description: "Cloud-native identity and workload boundaries; IAM role chains, metadata service, serverless triggers, Kubernetes and RBAC, mesh authorization, storage and signed-URL lifecycle."
---

# Cloud / Cloud-Native

Every cloud finding reduces to one boundary: **which identity** reaches **which resource**, and does the platform enforce it on the path you reached. Fingerprint the **provider and role model** first, then prove each claim with a **clean-session read-back** against researcher-owned objects only.

## Run this

1. **Baseline authenticated and unauthenticated responses** for the target function, storage object, or API endpoint, including status, body hash, and relevant headers. Done when every endpoint has both baselines recorded.

2. **Enumerate identity read-only** — from the authorized context, list the attached role or permissions through provider metadata or a self-scoped enumeration call, and stop before assuming any role. Done when the attached identity and its observed scope are written down.

3. **Probe metadata non-destructively** — one metadata-shaped read through an observed SSRF sink using a harmless path; token issuance or role-name disclosure is the oracle. Done when the sink method and its refusal-or-disclosure response are recorded.

4. **Run the storage lifecycle check** — create a researcher-owned object, grant then revoke or expire its share link, and re-request the URL from a clean anonymous session. Done when each lifecycle stage has a clean-session body hash to compare.

5. **Diff the mesh path** — same authorized and direct-path requests with one variable changed, confirming whether the authorization decision moves with the path. Done when both paths' decisions are recorded side by side.

6. **Limit every claim to researcher-owned scope** — the proof is an authorized action against your own object or tenant; naming, refusal, or error text alone is the control passing.

## Done when

- Every target endpoint has paired authenticated and unauthenticated baselines.

- Every identity, metadata, mesh, and storage probe has one result recorded on researcher-owned scope.

- Every escalation claim names the researcher object or permission it reached.

## Stop conditions

- Customer data, an unrelated tenant object, a live secret, or a cluster-wide effect appears — halt, record the oracle, clean up researcher objects, and report without lateral movement.

- A clean 403, connection refusal, or IMDSv2 token gate answers the probe — record it as the control passing and treat that path as hardened.

- A probe would assume a role, use disclosed credentials, or touch another account — stop at disclosure, report the oracle, and go no further.

## Depth

Field guide: `12_knowledge/cloud-cicd/cloud.md` — research families, oracle catalog, false-positive disambiguation, and IMDS, Kubernetes, serverless, mesh, and signed-URL version notes.
