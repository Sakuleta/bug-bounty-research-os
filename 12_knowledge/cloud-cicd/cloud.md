# Cloud / Cloud-Native

> SCOPE: Load when the target runs on AWS, GCP, Azure, Kubernetes, serverless, or a service mesh, or when IAM, workload identity, or storage boundaries are the research surface.

## Research families

- IAM role assumption chains and cross-account trust misconfiguration
- Workload identity binding (pod, function, or instance to cloud role)
- Instance and platform metadata service access (IMDS, GCE, IMDSv2 bypass context)
- Container credential endpoints (ECS relative-URI proxy, EKS Pod Identity agent) as a second metadata-shaped surface
- Serverless execution context (function URLs, event triggers, layer reuse, cold-start state)
- Kubernetes API, kubelet, etcd, dashboard, and RBAC exposure
- Admission-control surfaces: webhook configurations, ValidatingAdmissionPolicy, PSA namespace labels
- Pod and container escape primitives (service-account token, hostPath, privileged, socket)
- Service-mesh authorization gaps (mesh bypass, mTLS-only without authz, header trust, XFF/XFCC)
- Object storage and signed-URL lifecycle (expiry, revocation, permission downgrade, ACL drift)
- Storage public-access kill switches (S3 Block Public Access, GCS public access prevention, Azure `AllowBlobPublicAccess`) and what they do not cover
- Secrets handling (environment, mounted volumes, build-time leakage) and secret-manager policy surfaces (resource policies, cross-account grants, control-plane to data-plane self-grant)
- Tenant and namespace isolation in shared clusters and shared accounts
- Control-plane audit gaps: does the action appear in CloudTrail / GKE audit logs / Azure activity log at all
- Managed-identity federation across trust boundaries (cross-cluster "identity sameness", cross-project pools, federated identity credentials)
- Build-time identity reuse: CI OIDC/role credentials that outlive the build or are cached on shared runners

### Provider fingerprint matrix (fill this in before choosing a probe)

| Signal | AWS | GCP | Azure |
|---|---|---|---|
| IMDS host | `169.254.169.254`; IPv6 `[fd00:ec2::254]` (Nitro only) | `metadata.google.internal` → `169.254.169.254:80` | `169.254.169.254` (non-routable, host-only) |
| Anti-spoof guard | `X-aws-ec2-metadata-token` (IMDSv2) | `Metadata-Flavor: Google` / `audience` param | `Metadata: true` header; must NOT carry `X-Forwarded-For` |
| Cred shape | `PUT /latest/api/token` then GET `.../iam/security-credentials/` | ADC → `.../instance/service-accounts/default/token` | `/metadata/identity/oauth2/token` (managed identity) |
| Workload binding | IRSA / EKS Pod Identity, ECS task role | Workload Identity Federation: pool `PROJECT_ID.svc.id.goog` | workload identity federated credential |
| Signed proof | — | node `identity` JWT (needs `audience`) | pkcs7 attested doc, cert SAN `*.metadata.azure.com` |
| Container creds | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` → `169.254.170.2`; Pod Identity sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` → `169.254.170.23` | GKE metadata server serves the pod KSA directly | — |
| Secret manager authz | IAM + secret resource policy; `secretsmanager:GetSecretValue` | IAM only (`roles/secretmanager.secretAccessor` holds `secretmanager.versions.access`) | vault access policy (legacy) or Azure RBAC data plane |
| Storage public switch | Block Public Access, 4 independent settings at org/account/bucket/access-point | public access prevention `enforced`/`inherited` + org policy `storage.publicAccessPrevention` | account property `AllowBlobPublicAccess` + per-container access level |
| Function front door | Lambda function URL `AuthType: AWS_IAM` or `NONE` | Cloud Run invoker IAM check, or `allUsers` + `roles/run.invoker` | HTTP trigger `authLevel: anonymous/functions/admin` + keys |

## Preconditions

- Engagement scope explicitly covers the cloud asset, cluster, function, or storage bucket being tested.
- A reachable cloud-shaped surface: function URL, storage endpoint, Kubernetes API port, mesh sidecar, or metadata-shaped SSRF sink.
- Researcher-controlled identity and objects only; no access to other tenants, production secrets, or customer data.
- Fingerprinted provider and role model (which cloud, which orchestrator, which identity issuer) before hypothesis selection.
- For escape or lateral-movement claims: an already-authorized execution context (own pod, own function) as the starting point.
- For storage claims: a researcher-owned object with a known permission baseline in two sessions.
- For identity-federation claims: the researcher controls both the asserting workload and the target resource, or the target is a researcher-owned project/bucket.
- For RBAC claims: a researcher-held token whose verb list you enumerated (`kubectl auth can-i --list`) and a distinct target that the verb should not reach.
- For confused-deputy claims: a researcher-owned caller (SaaS-shaped principal, service principal, federated IdP tenant) plus a researcher-owned resource whose policy you can read — the question is always "which condition key is absent", never "does the service principal exist".
- For function-URL / Cloud Run / Functions claims: the exact `AuthType`/auth level of the route being hit, read from the platform API rather than inferred from a 200.
- For secret-manager claims: a secret in a research account you own, and a second principal whose only difference is the grant under test.

### Fingerprinting checklist (run before hypothesis selection)

1. Provider + orchestrator: which cloud, which managed K8s (EKS/GKE/AKS), which node pool / workload runtime, documented in the engagement scope.
2. Identity issuer: instance profile, IRSA/Pod Identity, GKE workload identity, Azure federated cred, or CI OIDC — name the *issuer* and the *audience* before any token probe.
3. Metadata reachability: is the IMDS host reachable from the workload at all, and are there proxy hops between the sink and the host (hop-limit-relevant)?
4. Container-credential surface: are `AWS_CONTAINER_CREDENTIALS_*` set, what host do they point to, and can the task/pod *also* reach IMDS despite that?
5. Verb inventory: enumerate the researcher subject's verbs (`kubectl auth can-i --list`) and flag the escalation verbs (`escalate`, `bind`, `impersonate`, `nodes/proxy`, `serviceaccounts/token`, CSR approval, webhook-config write).
6. Storage token model: is the signed URL created with a principal key or a temporary credential, and what is the credential's own lifetime? Which public-access kill switch exists at which level?
7. Secret access model: which principal can read secret values, at which resource level, and which principal can re-grant that (Key Vault Contributor/`write` + role-assignment permission, Secret Manager `setIamPolicy`)?
8. Admission surface: who can create/patch validating or mutating webhook configurations, and what PSA level is enforced per namespace?
9. Audit expectation: which control-plane log would record the candidate action, so an oracle can be confirmed from the audit trail (and a missing entry is itself a finding).

## Oracles

### Metadata / workload identity
- Metadata-service response differential: researcher-controlled fetch returns instance role name or token material versus a 403 or IMDSv2 token-required refusal.
- IMDSv2-enforcement oracle: GET-only SSRF sink returns `401 Unauthorized` with no body where a PUT-capable sink returns a token, role name, or temp credentials — the method capability, not the host, is the control.
- Hop-limit exit oracle: a SSRF that traverses one or more proxies still reaches metadata only if `HttpPutResponseHopLimit` >1; a value of 1 is the hardening passing, not a finding.
- GKE metadata-server binding oracle: from a pod, `.../instance/service-accounts/default/token` returns a federated token for the *pod's* KSA where the node SA (over-broad node pool SA) would be the weaker baseline — read-only, scoped to the namespace you own.
- Azure header-gate differential: request without `Metadata: true` (or with `X-Forwarded-For`) is rejected where the compliant request returns JSON — the guard is present; a bypass through a proxy that strips/adds those headers is the finding.
- Container-credential oracle (AWS): `GET http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (ECS) or the `FULL_URI` endpoint with the `AUTHORIZATION_TOKEN_FILE` bearer (EKS Pod Identity) returns credentials for the workload's *own* role — that is expected; the finding is credentials for a role other than the workload's, or reachability of the endpoint from a workload that should not have it.
- ECS isolation oracle: an `awsvpc` task with `ECS_AWSVPC_BLOCK_IMDS` unset/`false` still reaches `169.254.169.254` and the instance profile even though a task role is configured; bridge-mode tasks are blocked only by the operator-applied iptables DROP.
- Identity-sameness oracle: a KSA of the same name+namespace in a *second* researcher-owned cluster in the same workload-identity pool resolves to the same cloud identity (or, on a scoped target, a second cluster's workload gains access it was not meant to have).
- Attested-data oracle (Azure): a signed `/metadata/attested/document` (pkcs7) validates against a cert SAN under `*.metadata.azure.com` — its presence distinguishes a real Azure host from a spoofed metadata endpoint.
- GKE node-JWT oracle: `/computeMetadata/v1/instance/service-accounts/default/identity?audience=...` returns a node JWT; the `audience` parameter is required, so a sink that cannot set it is a weaker probe.

### Kubernetes / control plane
- Kubernetes unauthenticated signal: API version, health, or pod-list endpoint answers without credentials where the secure baseline is 401 or 403.
- `system:unauthenticated` binding: an anonymous request reaches a verb a hardened cluster reserves for authenticated subjects.
- `nodes/proxy` GET: a token whose only right is `get nodes/proxy` returns kubelet container logs or exec/attach — this is a write-equivalent that bypasses the API server's audit and admission (see Version notes).
- Direct-kubelet oracle: port 10250 answers `/pods` or `/runningPods` to an anonymous (`system:anonymous`) request when `--anonymous-auth` is left at its default and authorization is `AlwaysAllow` (also the kubelet default) — the secure baseline is 401 with `--anonymous-auth=false` plus webhook authorization.
- Escalation-verb oracle: a subject can `create` a Role/ClusterRole/Binding beyond its own rights via `escalate`, `bind`, or `impersonate`, or mint a client cert via CSR create + `certificatesigningrequests/approval`.
- Token-minting oracle: `create` on `serviceaccounts/token` yields a token for a ServiceAccount more privileged than the caller.
- Bound-token oracle: a token minted for a pod-bound ServiceAccount still validates *offline* after its bound pod is deleted — only the API server re-checks bound claims, so an external verifier that skips TokenReview accepts a stale token (see Version notes).
- Admission-surface oracle: `create`/`patch` on `validatingwebhookconfigurations` or `mutatingwebhookconfigurations` lets the subject read (and, when mutating, rewrite) every object admitted to the cluster.
- EKS access-entry oracle: a principal mapped through an EKS access entry with an AWS access policy (or a K8s group reference) reaches cluster verbs, and the grant appears in CloudTrail (`CreateAccessEntry`) where the legacy `aws-auth` ConfigMap left no AWS-side trail.
- PSA/namespace-label oracle: `patch` on a Namespace flips `pod-security.kubernetes.io/enforce` (or a NetworkPolicy-selecting label) to a weaker policy.

### IAM and policy
- Cross-account trust differential: a role whose trust policy names a broad principal (account root, wildcard service principal, or a condition on an attacker-controllable claim) is assumable from a researcher-owned identity where the secure baseline names an exact principal plus an external-ID/condition.
- Explicit-deny absence: an action that a hardened policy denies outright is allowed because only a broader `Allow` matches — confirm with two researcher-owned requests identical except for resource ARN/scope.
- Condition-satisfiability: a `aws:ResourceTag`-style / `resource.matchTag`-style condition is satisfiable by a tag the researcher can set on a resource they own.
- Session policy: a role assumable without MFA, or with a `max_session_duration` far above policy intent, widens the window a leaked token is usable.
- Self-check before escalation: "can the researcher subject do X to a *resource they do not own*" is the only escalation question that matters; anything reachable on the researcher's own objects is not.
- Policy-evaluation oracle: same principal, two resources or two actions — an `Allow` in an identity policy that stops working behind a permissions boundary/SCP/RCP is the intersection rule, not a bug; look for the action that is *not* capped by the boundary that the org believes caps it.
- Cross-account completeness oracle: a cross-account `lambda:InvokeFunction` succeeds only when both the identity policy and the function's resource policy grant it — a resource policy alone is not access, and an identity policy alone is not access.
- PassRole oracle: a subject with `iam:PassRole` (unconstrained by `iam:PassedToService` or a resource ARN) that can also create/update a compute resource can hand a role to that service; there is no `PassRole` CloudTrail event — the passed role appears only inside the resource-creating event (`CreateFunction`, etc.).
- Service-principal confused-deputy oracle: a resource policy that grants a service principal (`s3.amazonaws.com`, `cloudtrail.amazonaws.com`, `pods.eks.amazonaws.com`) without `aws:SourceArn`/`aws:SourceAccount`/`aws:SourceOrgID`/`aws:SourceOrgPaths` accepts that principal acting for *any* account, not only yours.
- Federated-credential oracle (Azure): an FIC whose `issuer`/`subject`/`audience` match is broad (org-level subject, wildcard segment, or a subject another party can request) mints an Entra token for a workload you control; matching is case-sensitive, so a token differing only in case must be rejected.
- WIF attribute-condition oracle (GCP): a workload identity pool provider without an `attributeCondition` accepts any identity the external IdP will mint (including for other clouds/tenants of the same IdP); the secure baseline rejects a credential whose `assertion` attributes fail the CEL condition.
- Function-URL auth oracle: `GetFunctionUrlConfig` reports `AuthType`; a `NONE` URL backed by a `Principal:"*"` resource policy answers an unauthenticated request, while an `AWS_IAM` URL with no matching `lambda:FunctionUrlAuthType` condition returns 403 — record both the config call and the raw request.
- Cloud Run oracle: the service object carries `run.googleapis.com/invoker-iam-disabled: 'true'`, or its IAM policy binds `allUsers` to `roles/run.invoker`; either gives anonymous invoke where the secure baseline is authenticated invoke.
- Functions key oracle (Azure): a route registered at the default `function` auth level returns 401/403 without `?code=` or `x-functions-key`, and 200 with any function key *or* host key — key presence, not key specificity, is what is enforced.

### Storage and signed URLs
- Signed-URL persistence: revoked, expired, permission-downgraded, or logged-out URL still returns the researcher-owned object bytes; a URL created with temp credentials that outlives the intent but follows the credential TTL is required, not assumed.
- Dual-path storage oracle: the same object shared through two mechanisms (share link vs. signed URL, or two access points) where revoking one leaves the other returning bytes.
- Header/cookie-gated signed URL: a URL that additionally requires a session cookie or signed header is not exposed by URL leakage alone — test the URL with and without the extra binding before claiming a finding.
- Cross-tenant leakage: object, secret, or log entry created by researcher tenant A is readable from researcher tenant B.
- S3 kill-switch oracle: a `PutBucketPolicy` granting `Principal:"*"` fails when `BlockPublicPolicy` is enforced at account level, yet the bucket can still be public through an ACL unless `IgnorePublicAcls`/`BlockPublicAcls` are on — read `GetBucketPolicyStatus` and `GetPublicAccessBlock`, never the policy text alone.
- GCS kill-switch oracle: adding an `allUsers` binding fails `412 Precondition Failed` under public access prevention where it succeeds without it; pre-existing `allUsers` grants stay in the IAM policy but requests fail 401/403 until the policy is edited.
- Azure container oracle: `AllowBlobPublicAccess: false` on the account overrides a container set to `Container`/`Blob`; the disallowed case returns 403 rather than 401, and static-website `$web` stays public regardless.
- SAS revocation oracle: only a *service SAS* bound to a stored access policy can be revoked by editing/deleting that policy; an ad hoc SAS (or any user-delegation/account SAS, which cannot use stored policies) is valid until expiry or until the signing key is rotated/disabled.

### Serverless / mesh
- Function-URL auth gap: unauthenticated request to a function or trigger endpoint returns the same authorized body as the authenticated baseline.
- Cold-start residue: second invocation in a fresh session observes a prior researcher-written temp value that should have been isolated per invocation.
- Function-concurrency residue oracle: two simultaneous researcher invocations of a function that should be isolated observe each other's canary in shared global state.
- Mesh-bypass differential: direct-to-service request succeeds where the same request through the mesh proxy is denied, or mesh mTLS passes but per-route authz is absent.
- Mesh authz oracle (Istio): with no ALLOW policy for the workload, requests are allowed; the moment one ALLOW policy exists, every request that it does not match is denied — so a route reachable from a namespace absent from `from.source` is the finding, and an explicit `DENY` must also exclude it (DENY is evaluated before ALLOW).
- Mesh identity oracle: `from.source.principals` is derived from the peer mTLS certificate (`<trust-domain>/ns/<ns>/sa/<sa>`), so a plaintext or PERMISSIVE-mode request carries no principal and fails a policy that requires one — use it to prove whether mTLS is actually enforced on the path, not just configured.
- XFF-trust oracle: `remoteIpBlocks` is populated from `X-Forwarded-For` and only resolves correctly when `gatewayTopology.numTrustedProxies` matches the real proxy chain; a client that can inject XFF entries in front of a mis-set trusted-proxy count shifts its apparent source IP.
- XFCC-trust oracle: the gateway's `forwardClientCertDetails` (default `SANITIZE_SET`) determines whether inbound `X-Forwarded-Client-Cert` is replaced by the verified client cert; a deployment set to `ALWAYS_FORWARD_ONLY` forwards client-supplied XFCC to the next hop.
- Mounted identity artifact: service-account token, cloud credential file, or ambient credential readable from the authorized execution context and usable only against researcher-owned scope.
- Secret-store oracle: `roles/secretmanager.secretAccessor` granted at project/folder/org level reads *every* secret under that scope, and a Key Vault Contributor (or any principal with `Microsoft.KeyVault/vaults/write` plus role-assignment write) can switch the vault to RBAC and grant itself a data-plane role — both are escalations visible as policy state, not as a secret read.

### Cross-family chains (compose verified primitives)

| Chain | Leg 1 (entry) | Leg 2 (escalation) | Leg 3 (persistence) | Oracle per leg |
|---|---|---|---|---|
| SSRF -> IMDS -> role | PUT-capable SSRF to metadata | IMDSv2 token -> temp creds | assume the role's downstream API | role name / creds returned |
| SSRF -> container creds | SSRF to `169.254.170.2` (ECS) or `169.254.170.23` (Pod Identity) | read task/pod role creds | call a researcher-owned API as that role | creds for a role not the sink's own |
| Pod -> node | `nodes/proxy` get | kubelet exec/logs | read node-SA creds | exec on a researcher pod |
| KSA -> cloud | over-broad node-pool SA | workload identity token | call a researcher-owned API as that SA | token audience/identity |
| Namespace patch -> weaker PSA | patch Namespace labels | schedule privileged pod | hostPath / node access | pod admitted under lowered policy |
| Leaked signed URL | token in logs/referer | URL still within cred TTL | object bytes fetched anonymously | byte hash match |
| FIC / WIF -> cloud | federated token from a second IdP tenant | federated credential/pool accepts it | call a researcher-owned API as the target identity | issued access token |

## Minimal safe proof

1. Baseline: record authenticated and unauthenticated responses for the target function, storage object, or API endpoint, including status, body hash, and relevant headers.
2. Read-only identity probe: from the authorized context only, list the attached role or permissions (for example provider metadata or role-enumeration call scoped to self, or `kubectl auth can-i --list`); stop before assuming any role or touching another account.
3. Metadata non-destructive check: attempt a single metadata-shaped read through an observed SSRF sink using a harmless path; treat token issuance or role-name disclosure as the oracle and halt before using the credential. If the sink is GET-only, record the refusal verbatim — it is a control, not a bug. For container creds, read the env var and one GET response only, and stop before using the credential.
4. Storage lifecycle check: create a researcher-owned object, grant then revoke or expire its share link (including the temp-credential-bound case), and re-request the URL from a clean anonymous session; compare body hashes. Then read the kill-switch state (`GetPublicAccessBlock`/`GetBucketPolicyStatus`, GCS PAP metadata, `allowBlobPublicAccess`) so the finding names the level that failed.
5. RBAC non-escalation check: as the researcher subject, run the candidate self-escalation verb against a resource you already own; confirm reachability of a *verb you were not granted* by any means short of invoking it on a privileged target.
6. Front-door check: for each function route, read the auth configuration from the platform API (`GetFunctionUrlConfig`, service IAM policy, trigger `authLevel`) and pair it with a key-less request; for each mesh route, diff the same request through and around the proxy.
7. Condition-key check: for a presumed confused-deputy gap, create a researcher-owned resource whose policy lacks (then includes) `aws:SourceArn`/`aws:SourceAccount` (or the provider equivalent) and show the caller you control is accepted only in the first case.
8. Stop conditions: any customer data, unrelated tenant object, live secret, or cluster-wide effect appears — halt, record the oracle, clean up researcher objects, and report without lateral movement.

## False positives

- Public-by-design buckets, function URLs, or health endpoints documented as public — rule out by checking scope intent and the absence of non-public data.
- Metadata address blocked with a clean 403 or connection refusal — that is correct hardening, not a finding; require returned role or token material.
- IMDSv2 token gate that refuses GET-only SSRF — refusals are the control passing, not exploitation; require a demonstrated bypass, not an assumption.
- IMDSv2 enforced account-wide (`HttpTokensEnforced=enabled`) yet a *launch* with `httpTokens=optional` fails closed — that is the enforcement working; only a runnable IMDSv1-capable instance is interesting.
- Role name visible in an error string with no usable permission — naming disclosure alone is not privilege escalation; require an authorized action on a researcher object.
- Own-pod service-account token readable inside the pod — expected mount behavior; require proof it reaches an out-of-scope API or another tenant. The same applies to the *default* mount when `automountServiceAccountToken: false` is set on the pod (pod setting wins over the SA default).
- Workload reading its own container credentials (`169.254.170.2`/`169.254.170.23`) — that is the credential provider working as designed; require a role other than the workload's own.
- Signed URL returning an error page with matching cache headers — the cache stored the error, not the object; require researcher object bytes.
- Cold-start timing jitter mistaken for state residue — rule out with repeated invocations and distinct canary values per run.
- Shared-cluster DNS or service names visible to all tenants — naming visibility without cross-tenant read or write is not isolation failure.
- `nodes/proxy` URL reachable but the caller lacks `get nodes/proxy` — the URL existing is not the oracle; the *verb grant* is what enables kubelet exec/logs.
- Deleting a service-account token file after use mistaken for revocation — a token already issued stays valid until its own expiry unless the issuer revokes it; check token TTL, not the file. For bound tokens the only per-token revocation is deleting the bound object or the ServiceAccount.
- "Role is assumable" as a finding when the role is the researcher's own or a documented shared role — require a permission or resource outside the researcher's grant to make it a finding.
- Service mesh present and enforcing mTLS treated as authz — mTLS proves transport identity, not per-route authorization; require a denied route to become reachable.
- Istio `PERMISSIVE` mode observed and reported as "mTLS off" — permissive is the documented migration state; the finding is a workload that still accepts plaintext after the strict-mode baseline the operator claims to run.
- Function URL public because the *staging* route is public — confirm production route auth against the platform's own routing, not a staging default.
- Lambda `NONE` auth URL returning 403 — that is the missing `lambda:InvokeFunctionUrl`/`lambda:InvokeFunction` resource policy or a `lambda:FunctionUrlAuthType` mismatch, i.e. the control, unless the resource policy genuinely grants `Principal:"*"`.
- Cloud Run `allUsers` in the IAM policy while the invoker IAM check is enabled — the check is the enforced control; verify which of the two mechanisms is actually active before reporting anonymous access.
- Azure container "public" because its access level is `Blob`/`Container` while the account's `AllowBlobPublicAccess` is false — the account setting overrides; the container is not anonymously readable.
- A permissive bucket policy on a bucket that contains only researcher-uploaded test objects — establish that any non-researcher object is reachable before claiming exposure. Likewise a GCS `allUsers` binding on a PAP-enforced bucket is a residue, not an exposure.
- IMDS reachable and returning a non-sensitive subset (hostname, instance-id, zone) with no token or credential material — the credential path, not the endpoint, is the finding.
- A signed URL that fails *after* the object is deleted attributed to "revocation not working" — deleting the object is not revoking the credential; test revocation with the object still present.
- SAS "revocation" attempted against an ad hoc SAS with no stored access policy — nothing was ever revocable except by rotating the signing key.
- Azure Functions 401 on a local (`localhost:7071`) test treated as host behavior — Core Tools disables key auth locally; re-test against the published host.
- Key Vault `Contributor` treated as a secret-read — it is control-plane only; the escalation is the ability to *grant* data-plane access, and the secrets themselves still require a data-plane role or access policy.

## Version/implementation notes

### AWS IMDSv2 and hop limit
- IMDS has two endpoints: IPv4 `169.254.169.254` (auto-enabled) and IPv6 `[fd00:ec2::254]` (opt-in, Nitro/IPv6 subnets only).
- `Metadata version` is `IMDSv1 or IMDSv2 (token optional)` or `IMDSv2 only (token required)`. IMDSv2 requires `PUT /latest/api/token` before GET; GET-only SSRF sinks fail closed while PUT-capable sinks stay high-yield — fingerprint the sink method first.
- `Metadata response hop limit` is `1`–`64`: the number of hops the PUT *response* may take. Hop limit `1` blocks the classic container/SSRF relay; container environments often set `2`.
- The `imds-support=v2.0` AMI parameter sets IMDSv2 + hop limit `2` (Amazon Linux 2023 defaults to IMDSv2-only for containers). Precedence is Instance launch > Account (per-Region) > AMI, evaluated per option; account-level enforcement is checked after precedence, and enabling it makes an IMDSv1-enabled launch fail.
- IAM/SCP condition keys can force IMDSv2, cap the hop limit, or disable IMDS entirely — an instance that still allows IMDSv1 despite an org policy is the interesting deviation.

### AWS container credentials (ECS and EKS Pod Identity)
- ECS sets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`; SDKs append it to the default host `169.254.170.2` and GET credentials from the agent (non-optimized AMIs need DNAT to the agent's local port plus `ECS_ENABLE_TASK_IAM_ROLE`). EKS Pod Identity sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` plus `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` (bearer token), served by the Pod Identity Agent on `169.254.170.23` ports `80`/`2703` (IPv6 `[fd00:ec2::23]`).
- ECS task credentials carry the `taskArn` in the CloudTrail session context, so a leak is attributable to a task; EKS Pod Identity assumes the role through the `pods.eks.amazonaws.com` principal on the node's behalf, so trust policies name that one principal instead of per-cluster OIDC providers.
- ECS documents plainly that containers on EC2 are not a security boundary: a task can reach the instance profile, other tasks' credentials, and IMDS unless blocked with `ECS_AWSVPC_BLOCK_IMDS=true` (awsvpc) or the Docker-user iptables DROP (bridge).
- EKS Pod Identity limits: up to 5,000 associations per cluster, Linux EC2 nodes only (not Fargate, Windows, Outposts, or self-managed clusters); pods with `hostNetwork: true` always have IMDS access even when Pod Identity supplies SDK credentials; associations are eventually consistent.

### AWS IAM evaluation, confused deputy, and PassRole
- Same account: identity-based + resource-based policies are a **union** (either allows); permissions boundaries and SCPs/RCPs are **intersections** with the identity grant when no resource policy applies; an explicit deny in any applicable policy wins.
- Cross-account: the request must be allowed by the identity-based policy *and* the resource-based policy on the target.
- Confused-deputy controls: `sts:ExternalId` for third-party AssumeRole, and `aws:SourceArn` / `aws:SourceAccount` / `aws:SourceOrgID` / `aws:SourceOrgPaths` for service principals; resource control policies (RCPs) can enforce the same centrally, and `aws:PrincipalIsAWSService` distinguishes service-principal calls in RCP conditions.
- `iam:PassRole` is a permission, not an API call — no CloudTrail event exists for it; constrain it by role ARN and `iam:PassedToService`, and do not try to constrain it with `aws:ResourceTag` (AWS documents that as unreliable).

### GCP / GKE Workload Identity Federation
- The cluster's workload identity pool is `PROJECT_ID.svc.id.goog`; GKE deploys a **GKE metadata server** (DaemonSet, one pod per Linux node) that intercepts `http://metadata.google.internal` (`169.254.169.254:80`). Traffic to it never leaves the VM.
- Token lifetime defaults to 1 hour (3,600 s); client libraries refresh when the token has <3 m 45 s left. Cached tokens can be returned near expiry.
- **Identity sameness**: workloads with the same KSA name + namespace in two clusters sharing the pool are the *same* IAM principal. This is the cross-tenant-class bug class when a shared pool spans clusters of differing trust; separate pools per project are the mitigation.
- Pods with `hostNetwork: true` bypass the GKE metadata server and reach the Compute Engine metadata server directly; with a strict network policy, pods need egress to `169.254.169.252:988` (or `169.254.169.254:80` on GKE Dataplane V2).
- Limits: 500 concurrent connections per node to the metadata server (excess queues → `HTTP/499`); >3000 KSAs per cluster can crash the metadata-server pods; node pools still use the node IAM SA to pull images.
- IAM principals are addressed as `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/NAMESPACE/sa/SERVICEACCOUNT` (single KSA) or `.../namespace/NAMESPACE` (all pods in a namespace, `principalSet://`). Wildcard-free principal sets are the correct least-privilege shape; a `principalSet` joined by namespace+cluster only is the over-broad case.
- By default the metadata server returns the identifier in the form `SERVICEACCOUNT_NAME.svc.id.goog`; add `iam.gke.io/return-principal-id-as-email: "true"` to the KSA to get a full IAM principal identifier back.
- The Security Token Service `Exchange Token` API is quota-limited (default 6,000 req/min) and can return `QUOTA_EXCEEDED`; a workload that silently falls back after that failure is worth noting.
- Cloud Storage FUSE CSI on host-network pods can authenticate as the pod's own KSA on cluster >= `1.33.3-gke.1226000`; older clusters fall back to the node SA.

### GCP impersonation, WIF pools, Secret Manager
- Service-account impersonation requires `iam.serviceAccounts.getAccessToken`, carried by roles such as `roles/iam.serviceAccountTokenCreator`; short-lived credentials are not auto-refreshed and create less risk than keys.
- Imposture is auditable where keys are not: when a principal impersonates a service account, most audit logs record **both** identities; a service-account key or an attached workload SA logs only the service account — the non-repudiation gap to note in a report.
- Workload identity federation separates *direct resource access* (`principal://`/`principalSet://` bindings) from *service account impersonation* (`roles/iam.workloadIdentityUser` on the target SA); grants should use the **project number**, not the project ID.
- Pool providers support OIDC, SAML, X.509, AWS, and local JWKs; `google.subject` is required and must be ≤127 chars; custom `attribute.*` values and `google.groups` drive `principalSet` scoping, and an `attributeCondition` CEL expression is the documented guard against the confused-deputy problem (e.g. accept only `attribute.aws_role == "<role>"`).
- Secret Manager grants apply at secret/project/folder/org level; `roles/secretmanager.secretAccessor` reads payloads (`secretmanager.versions.access`), while `roles/owner` includes that permission and `roles/editor`/`roles/viewer` do not. IAM Conditions can scope by date/time and by resource/version attributes.

### Azure IMDS
- IMDS is HTTP-only at `169.254.169.254`, reachable only from inside the VM, and is **unauthenticated and open to all processes** on the VM — treat anything it returns as tenant-visible. Firewall rules are the per-process mitigation.
- Every request needs header `Metadata: true`, must NOT include `X-Forwarded-For`, must bypass proxies, and must carry `api-version` (the `versions` endpoint is the only unversioned one).
- Rate limits: ~5 req/s per VM (429 beyond), but `/metadata/identity` allows ~20 req/s and 5 concurrent. `410 Gone` = retry within 70 s.
- Attested data is a pkcs7 blob over `vmId`, `sku`, `subscriptionId`, nonce and timestamps; validation checks the cert SAN against `*.metadata.azure.com` (global), `*.metadata.azure.us` (Gov), `*.metadata.azure.cn` (China), `*.metadata.microsoftazure.de` (Germany). `userData` is Base64 and must not hold secrets.
- IMDS calls must originate from the VM's primary NIC / primary IP, must bypass proxies even when none is configured, and need a route for `169.254.169.254/32` in the local routing table (failover clusters often need that route added).

### Azure workload identity federation and SAS
- A federated identity credential matches `issuer`, `subject`, and `audience` **case-sensitively** against the external token; supported issuers include GitHub Actions, any Kubernetes cluster, GCP, AWS (IAM outbound identity federation), SPIFFE/SPIRE, and Azure Pipelines service connections. Microsoft Entra-issued tokens cannot be used as the external token, and only the first 100 signing keys from the external OIDC endpoint are stored.
- Scope FICs at the narrowest subject the issuer gives you (repository + environment/branch, or KSA name+namespace); an org-wide or wildcard subject is the confused-deputy shape that lets another workload of the same IdP mint your identity.
- Azure Storage SAS types: **user delegation SAS** (signed with Entra credentials via a user delegation key; requires the `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey` action), **service SAS**, and **account SAS** (both account-key-signed). Stored access policies work only for service SAS (max 5 per container); user-delegation and account SAS must be ad hoc.
- SAS generation is not audited by the platform, and shared-key signed SAS keeps working until the signing key is rotated or Shared Key is disallowed on the account; clock skew up to 15 minutes applies to start/expiry. Treat a leaked account-key SAS as an account-key compromise, not a URL problem.

### Azure Key Vault and Functions
- Key Vault has two planes: control plane (ARM, always Azure RBAC) and data plane (legacy vault access policies or Azure RBAC). Azure RBAC became the default for newly created vaults with API version 2026-02-01+, and switching an existing vault to RBAC invalidates its access policies.
- Any principal with `Microsoft.KeyVault/vaults/write` plus role-assignment write (typically Contributor/Owner) can grant itself a data-plane role — control-plane access is effectively transitive data access; `Key Vault Contributor` alone is not a secret read.
- Data-plane roles to check: `Key Vault Secrets User` (read secret contents incl. certificate private key), `Key Vault Reader` (metadata only), `Key Vault Administrator` (all data-plane operations), with ABAC conditions (vault name, secret name) available on the RBAC path.
- Azure Functions HTTP triggers use `authLevel` `anonymous` | `function` (default) | `admin`; the key rides in `?code=` or the `x-functions-key` header, and **any function key or host key satisfies it**. Core Tools disables key auth locally; `/admin` and `/runtime` at the app root are host-reserved and never reach function code.

### Kubernetes RBAC and kubelet
- `system:masters` membership bypasses all RBAC *and* the authorization webhook and cannot be revoked by removing bindings; `system:unauthenticated` bindings expose whatever they grant to anyone who can reach the API.
- `get nodes/proxy` is not read-only: it reaches the kubelet API over the API server and enables container logs, exec, and attach even without the equivalent API rights, and it **bypasses audit logging and admission control**. Kubelet maps `/stats`→`nodes/stats`, `/logs`→`nodes/log`, everything else (incl. exec/attach websockets) to `nodes/proxy`, and a websocket `GET` is authorized as the `get` verb.
- Kubelet defaults are permissive: unauthenticated requests become `system:anonymous`/`system:unauthenticated` unless `--anonymous-auth=false`, and the default authorization mode is `AlwaysAllow` — webhook authorization (`SubjectAccessReview`) must be configured explicitly. Kubernetes v1.36 makes `KubeletFineGrainedAuthz` stable (`/pods`, `/runningPods`, `/healthz`, `/configz` checked individually before falling back to `nodes/proxy`).
- Privilege-escalation verbs to hunt: `escalate`, `bind`, `impersonate`; `create` on `serviceaccounts/token`; CSR create plus `certificatesigningrequests/approval` for `kubernetes.io/kube-apiserver-client` (mints client certs with arbitrary names); create/patch on `validatingwebhookconfigurations`/`mutatingwebhookconfigurations` (read or rewrite every admitted object); namespace-boundary weakness (within a namespace, "create workloads" ≈ "any ServiceAccount's API level").
- `list`/`watch` on Secrets reveals contents (a List returns all Secret values); permission to create workloads in a namespace implicitly grants that namespace's Secret/ConfigMap/PV mounts and *any* ServiceAccount's API level; creating PersistentVolumes allows `hostPath`.
- Namespace `patch` can flip Pod Security Admission labels, NetworkPolicy-selecting labels, or DRA `resource.kubernetes.io/admin-access: "true"` (admin access to allocated devices).
- Bound ServiceAccount tokens: the projected volume (via the TokenRequest API) is pod-bound with the API server as audience, default 1 h, refreshed by the kubelet; deleting the pod invalidates its tokens, and deleting/recreating the ServiceAccount changes the UID and invalidates **all** its tokens. There is no per-token revocation. Offline JWT validators that skip TokenReview do not re-check bound claims; legacy auto-generated secret tokens are marked invalid after 1 year of non-use (v1.29+) and purged later, while manually created secret tokens never expire.
- EKS access entries replace the `aws-auth` ConfigMap for new clusters: an entry associates an IAM principal with either an AWS-maintained access policy or a Kubernetes group reference, is managed through the EKS API (CloudTrail-logged), and requires the cluster's authentication mode to include the API (`API` or `API_AND_CONFIG_MAP`). Enabling access entries on a legacy cluster auto-creates only the cluster creator's entry — other `aws-auth` mappings are not migrated.
- CVE-2024-3177 (kube-apiserver): with the ServiceAccount admission plugin and the `kubernetes.io/enforce-mountable-secrets` annotation, containers/init/ephemeral containers using `envFrom` bypass the mountable-secrets policy. Affected v1.29.0–1.29.3, v1.28.0–1.28.8, ≤ v1.27.12; fixed v1.29.4, v1.28.9, v1.27.13. Audit-log signal: pod updates using `envFrom`.

### Signed URLs / presigned storage
- AWS presigned URLs are **bearer tokens** bounded by the generating principal's permissions and credential lifetime. Console expiry is 1 min–12 h; CLI/SDK up to 7 days for IAM-user SigV4 creds, but temp creds cap it ("whichever comes first").
- Temp-credential cap is the revocation story admins miss: ECS task role creds rotate ~1–6 h, STS `AssumeRole` sessions default 1 h, EC2 instance-profile metadata creds cap near 6 h. A URL "revoked" by deleting the object/role session stops working only when the underlying cred dies or the object disappears.
- `s3:signatureAge` (bucket/access-point policy condition) rejects URLs older than N ms; `aws:SourceIp` / `aws:SourceVpce` bind the URL to a network path. Absence of either is what makes a leaked URL portable.
- GCE/Azure/GCP object stores differ in query-parameter names, clock-skew tolerance, and whether the token is signed at creation or re-checked per request; re-test revocation from a clean session per provider.
- S3 Block Public Access is four settings (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) applied at org/all-or-none, account, bucket, and access point, with the most restrictive combination winning; a policy counts as public unless every principal is fixed or the condition uses a fixed `aws:SourceIp`/`aws:SourceVpc`/`aws:SourceVpce`/`aws:PrincipalOrgID`-class key (broad `aws:SourceIp` such as `0.0.0.0/1` still counts as public). Removing a setting re-exposes anything the stored policy or ACL still grants.
- GCS public access prevention is a bucket setting (`enforced`) or an org policy constraint (`storage.publicAccessPrevention` at project/folder/org, inherited); `allUsers`/`allAuthenticatedUsers` requests fail 401/403, adding such a binding fails 412, signed URLs and private-bucket-access are unaffected, and enforcement can take up to 10 minutes plus cache TTL to bite.
- Azure anonymous blob access needs both switches on: account `AllowBlobPublicAccess` and container level `Blob`/`Container`; the account disallow returns 403 (not 401) and leaves `$web` static-site data public by design.

### Serverless and service mesh
- Managed serverless platforms differ on function-URL auth defaults, trigger auth, and layer sharing; test the observed route rather than the platform default.
- Lambda function URLs: `AuthType` is `AWS_IAM` or `NONE`; since October 2025 new URLs require **both** `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` permissions, and `NONE` still requires a resource-based policy granting public access. Condition keys `lambda:FunctionUrlAuthType` (`AWS_IAM`/`NONE`) and `lambda:InvokedViaFunctionUrl` (bool) let policies restrict invocation to the URL path; cross-account callers need identity policy *and* resource policy.
- Lambda resource-based policies accept only `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID` when added via `AddPermission`, while `PutResourcePolicy` accepts full JSON (20 KB max) and **replaces** any prior policy; scope trigger grants with `aws:SourceArn`/`aws:SourceAccount` to avoid the S3/SQS confused deputy.
- Service meshes differ sharply: some enforce mTLS only while authz policies are opt-in per route — confirm per-route policy, not mesh presence.
- Istio `PeerAuthentication` sets inbound mTLS per workload: `UNSET` (inherit, else PERMISSIVE), `PERMISSIVE` (plaintext or mTLS), `STRICT`, `DISABLE`; `portLevelMtls` requires a workload selector and refers to the workload port, not the Service port; a `default` policy in the root namespace is mesh-wide and its workload selectors are ignored. In ambient mode `DISABLE` is unsupported and HBONE/ztunnel mTLS is always on.
- Istio `AuthorizationPolicy` evaluation: CUSTOM → DENY → ALLOW; with no ALLOW policy for the workload, requests are allowed; `spec: {}` denies all, `rules: [{}]` allows all; a DENY rule matching on an HTTP attribute against TCP traffic treats the missing attribute as a match, so DENY policies should always be scoped to a port; `from.source.principals` requires mTLS, and `remoteIpBlocks` requires `numTrustedProxies` in `meshConfig.defaultConfig.gatewayTopology` to resolve XFF correctly.
- Istio defaults worth diffing: path normalization is `BASE` (RFC 3986 + backslash conversion) unless set to `MERGE_SLASHES` or `DECODE_AND_MERGE_SLASHES`; `hosts` matching is exact-string while Envoy configs generate `host:port` variants, and `hosts` is meaningless for sidecar-enforced policy because the client controls the Host header; the `MeshConfig` gateway default for `forwardClientCertDetails` is `SANITIZE_SET`, and `ALWAYS_FORWARD_ONLY` is the value that forwards client-supplied XFCC.
- The mesh's security boundary is the *other* pod's sidecar: a pod may remove its own redirection and bypass outbound capture, and `outboundTrafficPolicy: REGISTRY_ONLY` is best-effort — egress gateways plus NetworkPolicy are the enforcement. Traffic capture misses UDP/ICMP and excluded ports, and `NetworkPolicy` should be layered underneath.
- Sidecar identity is often a namespace-wide ServiceAccount; a pod that can reach the sidecar admin port gains the mesh's identity even where its own RBAC is narrow. Port `15000` (Envoy admin) is localhost-only, `15090`/`15021`/`15020` are exposed (telemetry/health/Prometheus), and istiod debug surfaces (`8080`, `15010`, `15012`, `15014`) require authentication by default.
- CI/CD identity (OIDC trust, IRSA, instance profile on shared runners) can outlive the build: check whether the role is assumable from a non-build context and whether it was cached on a shared runner.
- Serverless runtime identity usually differs from the caller's: a function may execute as a role broader than its trigger auth implies, so compare the *caller* gate against the *runtime* role.
- Trigger auth vs front-door auth: message-queue, schedule, and internal HTTP triggers frequently bypass a function URL's authorizer; test each trigger path separately rather than the "public" URL alone.
- Layer / extension reuse: shared layers and platform extensions can carry stale credentials or state across invocations; treat a layer as attacker-supplied if it is unpinned by digest.
- Warmup / snapshot persistence: platforms that snapshot post-init state can carry a value written during warmup into later isolated invocations — the residue oracle below.
- Control-plane audit: verify the candidate action actually appears in the provider audit log (CloudTrail / GKE audit logs / Azure activity log). An action that completes without an audit entry is itself a reportable gap.

### IAM / role-assumption specifics
- AssumeRole trust is the seam: enumerate the trust policy's principal, `sts:ExternalId` condition, source-account, and MFA condition; a missing binding on any of these is the differential.
- Permission-boundary and SCP interaction: an `Allow` in an identity policy can still be capped by a boundary/SCP — an action that succeeds despite an intended cap is the finding, not the raw policy text.
- Session tagging and `aws:PrincipalTag` conditions: a role that sets its own session tags at assumption can satisfy a condition meant to gate a different principal class.

## References

- [T1 vendor] AWS EC2 IMDS configuration (IMDSv2 token via `/latest/api/token`, IMDSv1/v2 modes): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- [T1 vendor] AWS EC2 instance metadata options (IPv4/IPv6 endpoints, hop limit 1–64, `imds-support=v2.0` → hop limit 2, precedence, `HttpTokensEnforced`, IAM condition keys): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html
- [T1 vendor] AWS blog, get the full benefits of IMDSv2 and disable IMDSv1: https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/
- [T1 vendor] AWS Amazon Linux 2023 IMDSv2 defaults (v2-only, hop limit 2 for containers): https://docs.aws.amazon.com/linux/al2023/ug/imdsv2.html
- [T1 vendor] AWS ECS task IAM role (task credentials + `taskArn` audit context, container isolation caveats, `ECS_AWSVPC_BLOCK_IMDS`, bridge-mode iptables): https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- [T1 vendor] AWS SDK container credential provider (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`/`FULL_URI`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, default host `169.254.170.2`): https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
- [T1 vendor] EKS Pod Identity (agent DaemonSet on `169.254.170.23` ports 80/2703, `pods.eks.amazonaws.com` trust, hostNetwork IMDS caveat, 5,000-association limit): https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- [T1 vendor] EKS access entries (IAM principal to K8s permissions, access policies, `aws-auth` migration): https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
- [T1 vendor] AWS IAM policy evaluation logic (identity ∪ resource, boundary/SCP/RCP intersection, explicit deny): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- [T1 vendor] AWS confused deputy problem (`sts:ExternalId`, `aws:SourceArn`/`SourceAccount`/`SourceOrgID`/`SourceOrgPaths`, RCP example): https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- [T1 vendor] AWS IAM `iam:PassRole` (resource scoping, `iam:PassedToService`, no CloudTrail event for PassRole, ResourceTag caveat): https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- [T1 vendor] AWS Lambda function URL auth (`AWS_IAM`/`NONE`, dual-permission requirement, `lambda:FunctionUrlAuthType`/`lambda:InvokedViaFunctionUrl`, cross-account rule): https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
- [T1 vendor] AWS Lambda resource-based policies (AddPermission condition keys, `PutResourcePolicy` replace semantics, 20 KB cap): https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
- [T1 vendor] AWS Secrets Manager resource policies (cross-account grants, service-principal `aws:SourceArn`/`aws:SourceAccount`, `BlockPublicPolicy`): https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html
- [T1 vendor] AWS S3 Block Public Access (four settings, org/account/bucket/AP levels, "public" policy test, effective ACLs): https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- [T1 vendor] GKE Workload Identity Federation (pool `PROJECT_ID.svc.id.goog`, GKE metadata server, 1 h tokens, identity sameness, hostNetwork bypass, egress ports, 500-conn limit): https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- [T1 vendor] GKE, link Kubernetes ServiceAccounts to IAM (principal identifier syntax, service-account impersonation): https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- [T1 vendor] GCP service account impersonation (`iam.serviceAccounts.getAccessToken`, `roles/iam.serviceAccountTokenCreator`, dual-identity audit logging vs keys): https://cloud.google.com/iam/docs/impersonating-service-accounts
- [T1 vendor] GCP Workload Identity Federation (`principal://`/`principalSet://`, attribute mappings, `attributeCondition` confused-deputy guard, direct access vs impersonation): https://cloud.google.com/iam/docs/workload-identity-federation
- [T1 vendor] GCP Secret Manager access control (`roles/secretmanager.secretAccessor` and `secretmanager.versions.access`, hierarchy effects, IAM conditions): https://cloud.google.com/secret-manager/docs/access-control
- [T1 vendor] GCS public access prevention (`enforced`/`inherited`, org policy constraint, 401/403 + 412 behavior, signed-URL exception, propagation): https://cloud.google.com/storage/docs/public-access-prevention
- [T1 vendor] Cloud Run public (unauthenticated) access (invoker IAM check, `run.googleapis.com/invoker-iam-disabled`, `allUsers` + `roles/run.invoker`, managed constraint): https://cloud.google.com/run/docs/authenticating/public
- [T1 vendor] Azure Instance Metadata Service (`Metadata: true` + no `X-Forwarded-For`, `api-version` required, rate limits, managed identity endpoint, attested pkcs7 SAN `*.metadata.azure.com`, "not a channel for sensitive data"): https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- [T1 vendor] Microsoft Entra workload identity federation concepts (issuer/subject/audience case-sensitivity, supported issuers, 100-key limit): https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- [T1 vendor] Azure Storage SAS overview (user delegation vs service vs account SAS, stored access policy limits, revocation and key rotation, no SAS-generation audit, clock skew): https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
- [T1 vendor] Azure Blob anonymous access (`AllowBlobPublicAccess`, container Private/Blob/Container, 403 vs 401, `$web` exception): https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure
- [T1 vendor] Azure Key Vault RBAC (control vs data plane, `Key Vault Secrets User`, Contributor self-grant, RBAC default from API 2026-02-01, access-policy invalidation): https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- [T1 vendor] Azure Functions HTTP trigger (`authLevel` anonymous/function/admin, `?code=`/`x-functions-key`, any function or host key, local auth disabled, reserved `/admin`/`/runtime`): https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger
- [T0 standards] Kubernetes RBAC good practices (`system:masters`, `nodes/proxy` bypasses audit/admission, escalate/bind/impersonate, CSR, `serviceaccounts/token`, webhook-configuration control, Namespace patch → PSA/NetworkPolicy/DRA, list/watch Secrets, PV → hostPath, `automountServiceAccountToken: false`): https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- [T0 standards] Kubernetes kubelet authentication/authorization (anonymous default, `AlwaysAllow` default, TokenReview/SubjectAccessReview, kubelet resource mapping, websocket GET = get, `KubeletFineGrainedAuthz`): https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
- [T0 standards] Kubernetes managing Service Accounts (bound tokens via TokenRequest, 1 h default, pod/SA deletion semantics, no per-token revocation, legacy token invalidation): https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
- [T1 vendor] Istio PeerAuthentication (`UNSET`/`DISABLE`/`PERMISSIVE`/`STRICT`, `portLevelMtls`, root-namespace mesh-wide policy, ambient mode): https://istio.io/latest/docs/reference/config/security/peer_authentication/
- [T1 vendor] Istio AuthorizationPolicy (CUSTOM → DENY → ALLOW evaluation, implicit allow without ALLOW policies, principals/`remoteIpBlocks`/`serviceAccounts` semantics): https://istio.io/latest/docs/reference/config/security/authorization-policy/
- [T1 vendor] Istio security best practices (PERMISSIVE vs STRICT, mTLS ≠ authz, positive/negative matching patterns, path normalization, host matching, sidecar capture limits, admin ports, first-party vs third-party tokens): https://istio.io/latest/docs/ops/best-practices/security/
- [T1 vendor] Istio gateway network topology (`numTrustedProxies`, `X-Forwarded-For`/`remoteIpBlocks`, `forwardClientCertDetails` enum incl. `SANITIZE_SET`/`ALWAYS_FORWARD_ONLY`): https://istio.io/latest/docs/ops/configuration/traffic-management/network-topologies/
- [T1 vendor] EKS RBAC hardening: https://docs.aws.amazon.com/eks/latest/userguide/rbac-hardening.html
- [T1 vendor] Kubernetes official CVE feed (Security Response Committee): https://kubernetes.io/docs/reference/issues-security/official-cve-feed/
- [T1 vendor] AWS S3 presigned URLs (bearer semantics, 1 min–12 h console / 7-day CLI, temp-credential cap, `s3:signatureAge`, `aws:SourceIp`/`aws:SourceVpce`): https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
- [T2 research] Datadog Security Labs, EKS pod-to-IMDS credential theft vector: https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/
- [T2 research] Snyk, hardening AWS EKS with RBAC, secure IMDS, audit logging: https://snyk.io/blog/hardening-aws-eks-security-rbac-secure-imds-audit-logging/
- [T3 vuln intel] CVE-2024-3177, mountable-secrets policy bypass via `envFrom` (affected/fixed kube-apiserver versions): https://github.com/kubernetes/kubernetes/issues/124336
- [T2 research] PortSwigger Web Security Academy: SSRF including cloud-metadata context, access-control differentials
- [T1 vendor] OWASP guidance on cloud misconfiguration, serverless risks, and Kubernetes hardening
- [T1 vendor] Public cloud-hardening benchmarks for the observed platform (provider baseline and CIS-style guidance)
