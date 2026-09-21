# Supply Chain / CI-CD

> SCOPE: Load only when the repository, build, artifact, or deployment pipeline asset is explicitly in scope; pipeline access alone is never the finding.

## Research families

- Dependency confusion and private-package shadowing (registry priority, namespace reservation)
- Typosquatting and name-normalization collisions (PEP 503 folding, npm scope-to-registry association, case/separator variants)
- Lockfile and manifest integrity (unpinned ranges, lockfile bypass, transitive substitution)
- Build trigger trust (fork PR builds, external contributor scripts, label-gated workflows)
- Pull-request workflow trust (approval bypass, stale-review reuse, bot auto-merge)
- Webhook and integrator verification (unsigned events, wrong scheme/method, replayed deliveries, secret rotation)
- Webhook replay and dedupe (timestamp/nonce freshness, delivery-ID reuse)
- Artifact provenance and substitution (unsigned builds, mutable tags, registry overwrite, copied attestations)
- Container build secrets (build-arg, layer, cache, and history leakage)
- IaC state and plan exposure (state files, plan output, destroy-shaped operations)
- Deployment pipeline authorization (environment promotion, approver scoping, secret scoping)
- Runner and cache poisoning (shared runners, poisoned cache keys, artifact reuse across branches)
- Release-build integrity vs. cache reuse (a release/publish job must not consume a writable cache)
- Third-party action/workflow compromise by mutable-reference mutation (tag retro-move, fork of the action)
- Trusted-publishing / OIDC trust misconfiguration (over-loose publisher or trust-policy match)
- OIDC subject-claim confusion (path/namespace recycling, wildcard subject, reusable-workflow identity)
- Package publishing bypass of the intended review gate (direct publish vs. staged/approved release)

### Reference-integrity model (why mutable refs are the seam)

| Reference form | Immutable? | Attack shape | Verifiable oracle |
|---|---|---|---|
| `owner/action@v4` (tag) | No — tags can be moved/deleted | retroactive tag → malicious commit | resolved commit differs from the tagged release |
| `owner/action@<full-sha>` | Yes (barring SHA-1 collision) | requires a valid Git object collision | digest matches a known-good commit |
| `pkg@^1.2.0` (range) | No | transitive substitution / newer bad version | lockfile vs. manifest resolution diff |
| `pkg@sha256:<digest>` / pinned digest | Yes | registry overwrite not reachable | pulled digest equals pinned digest |

## Preconditions

- The pipeline asset under test is in scope with a named owner and an explicit test boundary.
- Researcher-controlled fork, branch, or package namespace where the program permits external contributions.
- Baseline of the legitimate build or release flow (who approves, what signs, where artifacts publish) before claiming a trust gap.
- Webhook or integrator hypotheses tied to an observed endpoint, secret scheme, or delivery log — not a speculative integration.
- Any secret-shaped string treated as a lead until it produces an authorization oracle on researcher-owned scope.
- For action-compromise claims: an action/workflow reference whose *resolved* digest you can compare against its published release, plus a researcher fork to test behavior without touching upstream.
- For trusted-publishing claims: a researcher-owned package whose publisher configuration you control, and a second workflow/repo from which you attempt to publish.
- For provenance claims: a consumer-side verifier available (your own install/pull path), not just an attestation present on the registry page.
- For webhook claims: a receiver you control that logs the raw body plus every header — the signature is computed over bytes and headers, not over parsed JSON.
- For OIDC claims: the trust policy/condition keys (or the decoded claims from a researcher-owned workflow in the same repository) before claiming confusion.
- For cache claims: a workflow whose trigger is on the write-capable list and whose cache scope resolves to the default branch; verify both before claiming poisoning.
- For NuGet claims: the package is not already in the global packages folder — a cached package never triggers a source lookup.

### Fingerprinting checklist

1. CI platform + trigger: which events fire the workflow (`pull_request`, `pull_request_target`, `workflow_run`, `workflow_dispatch`), and does each have secrets/write?
2. Reference forms: enumerate every `uses:`/workflow ref and every dependency range; flag the mutable ones.
3. Secret scoping: org/repo/environment/`GITHUB_TOKEN` defaults; who can read each secret, and which environments gate them.
4. Publish path: token-based, OIDC trusted publishing, or staged; which is allowed, and can a lower-trust workflow reach it.
5. Provenance: attestation present **and** verifier the consumer runs; a signature nobody checks is not a control.
6. Runner trust: hosted vs. self-hosted; if self-hosted, what lives on the machine and who can reach it.
7. Webhook scheme: which header, which algorithm, whether a timestamp/nonce exists, and whether comparison is constant-time.
8. OIDC identity: which claims the trust policy matches (`sub` vs `job_workflow_ref` vs `repository_id`), whether wildcards are used, and whether the repo uses immutable subject claims.

## Oracles

- Confusion-order signal: private package name resolves to a researcher-controlled public version in a clean install where the secure baseline prefers the private feed.
- Unpinned-substitution differential: lockfile build and manifest-only build resolve different versions of the same researcher-owned dependency.
- Fork-build execution: researcher fork PR triggers a build step that reads a protected secret or writes to a protected branch or artifact feed.
- Approval-bypass confirmation: single-approval or bot-merged researcher PR promotes to a protected environment the baseline requires two human approvals for.
- Webhook acceptance gap: unsigned or replayed delivery with researcher payload is accepted where the secure baseline demands signature plus timestamp plus nonce.
- Mutable-tag substitution: artifact digest behind a floating tag changes without a new authorized build record, and a consumer pulls the substituted bytes.
- Build-secret residue: image layer, build cache, or log for a researcher build contains a secret-shaped value retrievable by an unauthorized researcher session.
- IaC-state disclosure: state or plan output exposes a researcher-owned secret or a cross-tenant resource address beyond the authorized reader set.

### Action / workflow integrity oracles
- Tag-resolution oracle: `owner/action@v4` resolves to a commit that is **not** the commit of the `v4` release; a retro-moved tag is the compromise signal (see CVE-2025-30066 in Version notes).
- Secret-in-log oracle: a build step's log echoes a masked value in a form redaction does not cover (base64, split, structured blob) — reproduce with a researcher secret you control.
- Cache-poisoning oracle: a cache key writable from an unprivileged workflow is read by a privileged workflow (`pull_request_target`/`workflow_run` share the main branch cache).
- Self-hosted-runner oracle: a researcher-driven workflow observes another job's environment/`ps` output, or reaches a service the hosted runner would not.

### Webhook verification oracles (per platform)

| Platform | Signature carrier | Scheme | Gap oracle |
|---|---|---|---|
| GitHub | `X-Hub-Signature-256: sha256=<hex>` | HMAC hex digest over the raw UTF-8 body only — no timestamp | Receiver that skips verification when the header is absent (it is absent when no secret is configured) accepts forged bodies; a captured valid delivery replayed with the same `X-GitHub-Delivery` GUID is processed twice unless the receiver dedupes |
| GitLab | `webhook-signature: v1,<base64>` | HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{body}` (Standard Webhooks); legacy `X-Gitlab-Token` is a plain-text header | Receiver still verifying only `X-Gitlab-Token`, or verifying the signature but never checking `webhook-timestamp` freshness, accepts a replay; a plain-text token compared with `==` is a timing oracle |
| Bitbucket Cloud | `X-Hub-Signature: <method>=<hex>` (WebSub format; currently `method=sha256`) | HMAC hex digest with the algorithm named in the header; docs warn the method may change | Verifier that hardcodes GitHub semantics for the same header name rejects valid deliveries; verifier that ignores `method` cannot adapt when it changes; body must be hashed verbatim (re-serialized JSON fails closed) |
| Stripe | `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]` | HMAC-SHA256 over `{t}.{raw body}`; multiple `v1=` entries are allowed and any match passes | `constructEvent()` applies a 300 s default tolerance; the lower-level `verifyHeader()`/`verifyHeaderAsync()` default tolerance is `0`, which skips timestamp verification entirely — replay protection depends on which function the app calls |

### CI OIDC trust oracles
- Wildcard subject live check: decode `sub` from a researcher-owned workflow on an unreviewed branch; if a policy using `StringLike` with `repo:ORG/REPO:*` (any branch, pull-request merge branch, or environment) lets that job assume the cloud role, the wildcard is the finding.
- Environment-claim mismatch: `sub` contains `:environment:<name>` only when the job references an environment; without one it is `...:pull_request` or `:ref:refs/...`. A policy that matches only the environment form, or a workflow that drops `environment:` to get a different subject, is the observable differential.
- Reusable-workflow identity: a caller repo running a reusable workflow keeps its own `repository`/`sub` while `job_workflow_ref` names the reusable workflow's repo and path — a policy keyed on `job_workflow_ref` alone without a repo/sub condition is the seam.
- Namespace-recycling oracle: for a repository using the pre-2026 `sub` name format, delete/rename the owner namespace and observe whether a newly created namespace with the same name obtains a token whose `sub` matches the old trust policy (immutable `owner_id`/`repo_id` subjects close this).
- Registry side: a workflow whose repository, workflow filename, or environment does not exactly match the trusted-publisher config still obtaining a publish token (see trusted-publishing oracles below).

### Trusted-publishing / publish-path oracles
- Publisher-match gap: a workflow whose repository, workflow filename, or environment does **not** exactly match the trusted-publisher config still obtains a publish token (or matches because a field is optional).
- Gate-bypass oracle: direct `npm publish` succeeds where policy requires staged review, or the token path is still open despite "disallow tokens".
- Provenance-verification gap: the registry shows a provenance attestation but the consumer's install/pull path never verifies it, so a substituted artifact with a copied attestation installs.

### Cache and artifact oracles (additions)
- Read-only enforcement check: save a cache from a low-trust trigger that resolves to default-branch scope; the platform answers with a warning and no cache write ("save failed", job continues) — that warning is the mitigation working, not a finding. A *successful* save means the trigger is write-capable (or the platform predates the change).
- Client-controlled hit: cache hits match a key plus a version string that the client controls; a privileged restore that returns attacker-seeded content under the victim's key is the substitution.
- Release-path cache use: a release/publish job with package-manager caching enabled (`cache: npm`, setup-node cache) restores whatever the cache holds — provenance attestation still verifies because it attests the build, not the file tree.
- Attestation-verification gap: a consumer that never runs the verifier (`gh attestation verify PATH/TO/ARTIFACT -R owner/repo`) installs an artifact carrying a copied attestation.

### Dependency-resolution oracles
- Feed-order differential: resolve the same request with the public feed reachable vs. unreachable and compare which registry/publisher wins.
- Lockfile-vs-manifest: `npm ci` (lockfile honored) and `npm install` after deleting the lockfile resolve different versions/provenance for the same researcher-owned dependency.
- Transitive swap: a direct dependency's *transitive* dependency resolves to a researcher-controlled namespace even when the direct dependency is pinned.
- Override/redirect: a resolver `overrides`/`resolutions`/`replace` entry silently redirects a package to a different source than the manifest implies.
- Normalization collision (Python): PEP 503 folds case and runs of `.`, `-`, `_` to a single `-`, so a requirement spelled `foo.bar`, `Foo_Bar`, or `foo-bar` resolves to the same package — publish the colliding spelling under a researcher-owned name and observe which one the resolver picks.
- Scope-registry association (npm): `@scope:registry` routes every `@scope/*` install and publish to that registry only; an internal package left unscoped, or a scope without an association, falls back to the public registry.
- Source-mapping bypass (NuGet): once mapping is enabled, mappings apply to restore/install/update but **not** to packages already in the global packages folder, and query commands still send IDs to all configured sources — test the restore path, not `dotnet list package`.

### Cross-family chains (compose verified primitives)

| Chain | Leg 1 (entry) | Leg 2 (escalation) | Leg 3 (persistence) | Oracle per leg |
|---|---|---|---|---|
| Tag-mutation -> secret read | action tag resolves to a foreign commit | step reads runner-visible secret | secret appears in public log | resolved digest != release commit |
| Fork PR -> privileged cache | unprivileged `pull_request` writes cache | `pull_request_target` reads it | code executes with secrets | cross-context cache read |
| OIDC publisher -> artifact | mismatched workflow gets token | publishes over-version | consumers pull bad artifact | publish succeeds on mismatch |
| Confusion -> build | private name resolves public | build vendored the canary | artifact embeds canary | resolver shows public win |
| IaC plan -> secret | plan output exposes secret | state read by wider set | destroy/replace triggered | unauthorized reader sees value |
| Cache -> release artifact | untrusted trigger seeds a key | release job restores it | provenance still verifies | cache hit in release job with a file not in the commit |

## Minimal safe proof

1. Baseline: record the legitimate dependency resolution, build trigger matrix, approval chain, and artifact digest for a researcher-owned change.
2. Confusion check (read-only): publish a canary version under a researcher-owned namespace only; never squat a private package name in a public feed — infer order from resolver output and error text.
3. Trigger matrix: open one researcher fork PR and one branch PR with one variable changed; record which steps execute, which secrets are masked, and which writes are attempted — abort on any protected write attempt.
4. Webhook replay: capture one legitimate delivery to a researcher endpoint (raw body + headers), then replay it once unsigned and once with an expired timestamp — for GitLab that means an aged `webhook-timestamp`; for GitHub, replay with the same `X-GitHub-Delivery` GUID (the signature carries no timestamp); for Stripe, an aged `t=` value. Compare accept versus reject decisions.
5. Provenance check: pull the artifact by tag twice across two authorized builds and compare digests plus signature presence; record mutable-tag drift without overwriting anything. Then run the *consumer-side verifier* (do not stop at "attestation exists").
6. Action-integrity check (read-only): for each third-party action ref, resolve the tag to a commit and compare against the release tag's commit; a mismatch is the finding and needs no execution.
7. Trusted-publisher check (read-only): attempt a publish from a second researcher-owned workflow with one field deliberately mismatched; a success on the mismatch is the oracle.
8. OIDC claim check (read-only): print the decoded `sub` and related claims from a researcher-owned workflow (the `github/actions-oidc-debugger` action or an `id_tokens` echo on GitLab) and diff them against the trust policy's conditions; attempt role assumption only from a context the policy author did not intend.
9. Cache write-capability check (read-only per default): classify each workflow trigger against the write-capable list, then let one untrusted-trigger run attempt a cache save; a read-only warning with no write is the platform defense, a successful write is the differential.
10. Stop conditions: any production artifact overwrite, real secret disclosure, cross-tenant pipeline effect, or protected-branch write — halt, preserve the oracle output, clean up researcher artifacts, and report without further interaction.

## False positives

- Private package name absent from the public feed with resolver error — correct reservation, not confusion; require researcher-controlled resolution.
- Fork builds running with secrets redacted and no protected writes — expected sandboxing; require a read or write beyond the sandbox.
- Bot merge on a repo whose policy explicitly allows it — policy-conformant automation; require promotion beyond the documented policy.
- Unsigned webhook accepted on a documented public event with no privileged action — intended openness; require a privileged state change.
- Mutable tag moving after an authorized rebuild — normal release flow; require substitution without an authorized build record.
- Secret-shaped placeholder (`xxxx`, `test`, `example`) in logs or layers — fixture data; require a live-format value validated as active only against researcher scope.
- IaC plan echoing researcher-supplied input back to the author — self-reflection; require disclosure to an unauthorized researcher session.
- Shared-runner slowness or queueing mistaken for cache poisoning — rule out with fixed cache-key repeats before claiming cross-branch contamination.
- A third-party action whose tag moved **to the same commit** (a re-tag/rename) — digest unchanged, no substitution; only a *different* commit is the signal.
- `GITHUB_TOKEN` with write permission when the workflow legitimately deploys — write is expected in the deploy job; require a write from a job that should not have it.
- Provenance attestation present and the consumer *does* verify — correct posture even if the attestation is unsigned at L1; require the specific missing check (L2/L3).
- A secret-looking value produced by the researcher's own build step — self-disclosure; require a secret the researcher did not supply.
- An action resolved from a *fork* the maintainer legitimately uses (documented mirror) — verify provenance (which repo the SHA belongs to) before calling it a substitution.
- A staged-publish approval step that exists but a maintainer routinely rubber-stamps — the control is present; require a bypass of the mechanism, not weak human habit.
- OIDC publish "succeeding" from a template repo because the program authorized it — read the trusted-publisher config; a deliberate broad match is policy, not a bug.
- Missing `X-Hub-Signature-256` on a GitHub delivery because the webhook has no secret configured — acceptable only if the endpoint performs no privileged action; it is a gap when state changes depend on it.
- A Stripe receiver that fails verification because a framework parsed, re-encoded, or whitespace-normalized the body — receiver implementation bug, not a Stripe gap; still a finding only if unverified events drive privileged state.
- `verifyHeader(tolerance = 0)` skipping timestamp checks — that is the SDK's documented default for the lower-level method; require evidence the app relies on it as its replay defense.
- A cache "save failed" warning from an untrusted trigger on github.com — the June 2026 mitigation working; not poisoning.
- A fork PR reading base-branch caches — documented platform behavior since caches are not secrets; only a finding if the cached path holds credentials.
- A package resolved from the global packages folder while source mapping is enabled — mapping is not exercised for already-cached packages; clear the folder per-repo first.
- A GitLab masked value appearing unredacted because the output transformed it (shell escaping) — masking is best-effort exact-match; require the raw value to be echoed.
- Absence of `pypi:tracks`/alternate-locations metadata — PEP 708 was rejected, so pip has no such mechanism; its absence is not a missing control.
- A trust policy written for the pre-immutable `sub` format on a repo created after 2026-07-15 — format drift, not claim confusion; match the format the repo actually issues.
- A Bitbucket `X-Hub-Signature` header mis-parsed by a receiver built for GitHub's same-named legacy SHA-1 header — implementation defect; require an acceptance/rejection differential with a correctly signed payload.
- NuGet query commands (`dotnet list package ...`) contacting public sources — documented mapping gap, not a restore-path compromise; only restore/install/update are mapped.

## Version/implementation notes

### Webhook verification by platform
- **GitHub**: signature is `X-Hub-Signature-256`, HMAC-SHA256 hex digest prefixed `sha256=`, computed over the raw body; docs test vector (secret `It's a Secret to Everybody`, payload `Hello, World!`) yields `sha256=757107ea...`. `X-Hub-Signature` (SHA-1) remains only for legacy. Compare with `secure_compare`/`crypto.timingSafeEqual`; the header is absent if no secret is configured. No timestamp is part of the scheme, so replay protection is the receiver's job.
- **GitLab**: new webhooks should use a **signing token** — delivery follows the Standard Webhooks spec with `webhook-id`, `webhook-timestamp`, and `webhook-signature: v1,{base64}` (HMAC-SHA256 over `{message_id}.{timestamp}.{body}`; the token is base64 after the `whsec_` prefix). The legacy **secret token** is sent as plain text in `X-Gitlab-Token` and should be replaced. Validate timestamp freshness to block replays. Both can run in parallel during migration.
- **Bitbucket Cloud**: the secret produces `X-Hub-Signature` with a WebSub-style `method=signature` value; Bitbucket currently sends `sha256` but states this may change, so verifiers should read the method. The payload is hashed verbatim — any reformatting changes the digest.
- **Stripe**: use `constructEvent(raw_body, Stripe-Signature, endpoint_secret)`; the secret starts with `whsec_` (CLI vs Dashboard secrets differ). The header parses to `t=...,v1=...` (legacy `v0=` may appear); multiple `v1` values support rotation and one match passes. The body must be the untouched UTF-8 string — Express needs `express.json()` registered after the webhook route, and some frameworks/AWS API Gateway need explicit raw-body handling.

### CI OIDC claims and trust (GitHub / GitLab)
- GitHub token claims: default `aud` is the repository-owner URL; subject formats are `repo:ORG/REPO:environment:NAME` (job references an environment), `repo:ORG/REPO:pull_request` (PR event, no environment), and `repo:ORG/REPO:ref:refs/heads|tags/...` otherwise; `:` inside values is encoded `%3A`. Custom claims include `job_workflow_ref`, `job_workflow_sha`, `workflow_ref`, `repository_id`, `repository_visibility`, `runner_environment` (`github-hosted`/`self-hosted`), and organization-defined `repo_property_*` ABAC claims. Dependabot update jobs carry `event_name: dynamic`.
- Repositories created after **July 15, 2026** use an immutable default subject that embeds owner and repository IDs (`repo:OWNER@OWNER-ID/REPO@REPO-ID:...`); older repositories keep the name-only format until they opt in via the OIDC settings UI/REST API, and renames/transfers after that date move to the immutable format. Trust policies must match the format the repository actually issues.
- Fetching a token needs `permissions: id-token: write` (workflow or job level); it grants no other access. Reusable workflows outside the org/enterprise require the caller to set the permission explicitly.
- AWS cannot use GitHub custom claims; matching is done on `token.actions.githubusercontent.com:sub` (and `:aud`). The AWS guide's own wildcard example, `StringLike: repo:octo-org/octo-repo:*`, deliberately allows **any branch, pull request merge branch, or environment**; environment protection rules are the recommended extra gate.
- GitLab ID tokens: `sub` defaults to `project_path:{group}/{project}:ref_type:{type}:ref:{branch_name}` and is configurable per project with `ci_id_token_sub_claim_components`; the claim can carry `ref_protected` and, for jobs with an environment, `environment_protected`/`deployment_tier`. Issuance is **blocked when the project path was previously used by another project** — the fix is to put `project_id` first (`project_id:<id>:ref_type:<type>:ref:<ref>`). Tokens are RS256 and expire at the job timeout (5 minutes if none is set).
- GitLab AWS guidance: for `gitlab.com` the IdP exposes condition keys including `project_id`, `namespace_id`, `ref_protected`, and `pipeline_source`; self-managed/dedicated expose only `sub`. Do not key a policy on `user_login`/`user_email` alone (user-changeable).

### Cache poisoning and release-build integrity
- Since **June 26, 2026**, github.com issues **read-only** cache tokens to the default-branch scope for triggers an outside actor can initiate that resolve to that scope (`pull_request_target`, `issue_comment`, fork-`workflow_run` cascades). Trigger list that keeps read-write caching: `push`, `schedule`, `workflow_dispatch`, `repository_dispatch`, `delete`, `registry_package`, `page_build`; `pull_request` is unaffected because its caches are scoped to `refs/pull/.../merge`. A blocked save logs a warning and does not fail the job; `actions/cache/restore` is the restore-only form.
- Cache restore order: exact `key`, then prefix, then `restore-keys` in order, searching the current branch first and the default branch second; the most recent partial match wins. Cache version is a hash of the cached paths plus compression tool, so identical text keys can still miss.
- Cache contents are **not signed or verified**; docs state anyone who can open a pull request can read base-branch caches, and forks can read base-branch caches — never cache secrets.
- Cacheract (Dec 2024) demonstrates the class: hits are key+version strings the client controls; a poisoned entry can overwrite files executed by later jobs (its demo replaced an action's `action.yml` and reached a release job through npm caching). GitHub has since restricted post-job cache writes and (2026) untrusted default-branch cache writes; the demo also showed the release's Sigstore provenance verifying even though the injected file was never in the commit.
- CodeQL query `actions/cache-poisoning/direct-cache` (security severity 7.5) reports write-capable workflows that cache untrusted files; GitHub's own recommendation is no caching for release jobs. The npm provenance docs set `package-manager-cache: false` with the comment "never use caching in release builds".

### Artifact attestations (GitHub)
- GitHub artifact attestations alone provide **SLSA v1.0 Build Level 2**; moving the build into a shared reusable workflow (isolation between build and caller) can reach **Level 3**.
- Attestations use Sigstore: public repositories use the Sigstore Public Good Instance (bundle stored with GitHub plus an immutable public transparency log); private repositories use GitHub's Sigstore instance, which has **no transparency log** and federates only with GitHub Actions.
- Consumer verification is `gh attestation verify PATH/TO/ARTIFACT-BINARY -R owner/repo` (or `-o organization`); GitHub warns that an attestation is not a guarantee the artifact is secure, only a link to source and build instructions.

### Dependency ecosystems
- **npm**: a scope is a namespace owned by a user/organization, and only its owner can publish into it; `npm config set @myco:registry=<url>` (or `npm login --scope`) routes every install/publish for that scope to the private registry. Scope-to-registry is many-to-one. An internal package left unscoped has no such guarantee — that is the confusion seam; the standard fix is to scope internal packages and pin the scope to the private registry.
- **pip**: secure baseline is hash-checking mode — `--require-hashes` is all-or-nothing (one `--hash` turns it on for all requirements and all transitive dependencies, which must also be pinned). Hash fragments served by PyPI (`#sha256=...`) are protection against download corruption only and do **not** satisfy `--require-hashes`. PEP 708 (repository `tracks` / alternate-locations metadata) was **rejected** in April 2026, so pip still flattens all configured repositories into one namespace and passes the combined file list to the resolver, which picks the best match irrespective of which repository served it — `--extra-index-url` ordering is not a control.
- **NuGet**: Package Source Mapping (NuGet 6.0+, Visual Studio 17.5+ UI) filters which sources NuGet searches per package ID. Once `<packageSourceMapping>` exists, every top-level **and transitive** ID must match a pattern (`*`, `Contoso.*` prefixes, or exact IDs); the most specific pattern wins. It applies to restore/install/update only — metadata/query commands still hit all sources, and a package already in the global packages folder is used without a source lookup.
- Registry behavior differs per ecosystem (npm, PyPI, Maven, Go, NuGet) on namespace reservation, proxy order, and upstream priority; test the observed feed, never assume npm semantics everywhere.
- CI platforms differ on fork-secret masking, `pull_request` versus `pull_request_target` semantics, and environment approver scoping; confirm the observed workflow file.
- Provenance formats (SLSA, Sigstore, vendor attestations) differ in what they sign and what verifiers check; a signature present but unverified by the consumer is the productive gap.
- Container builders differ on layer caching, secret mounts versus build-args, and history retention; inspect the observed Dockerfile and builder version.
- IaC backends differ on state encryption, locking, and plan-output redaction; backend configuration governs the disclosure surface.

### GitHub Actions — trigger and reference trust
- `pull_request_target` and `workflow_run` are **privileged** triggers: they run in the context of the base repository, share the main branch's cache with other privileged runs, and may hold repository write and secrets. They must not check out untrusted fork code. `workflow_run` is the safer trigger for privilege separation when the workflow genuinely needs the privileged context.
- Pinning an action to a **full-length commit SHA** is the only immutable reference; tags can be moved or deleted by anyone who compromises the action's repository. Verify a SHA comes from the action's repo, not a fork.
- Dependabot alerts only fire for actions pinned with semantic versioning — **SHA-pinned actions do not generate Dependabot vulnerability alerts**, so pinning trades automated monitoring for immutability (complement with dependency review / Scorecards).
- OpenSSF Scorecard's `Dangerous-Workflow` check flags risky `pull_request_target`/`workflow_run` patterns; use it before manual review.
- Self-hosted runners should almost **never** be used for public repositories (anyone can open a PR and compromise the environment); a persistent runner also exposes other jobs' secrets via `ps x -w`. Just-in-time (JIT) single-job runners reduce, but do not eliminate, cross-job exposure.
- Secret masking is best-effort: register every derived value (`::add-mask::VALUE`, core `setSecret`) because redaction is exact-match based — a JSON/XML/YAML "structured" secret, or a base64-transformed value, is not reliably redacted.
- GitHub OIDC custom claims are **not supported in AWS**; a trust policy cannot rely on a custom GitHub claim there.
- Audit-log events such as `org.update_actions_secret` reveal who changed secret scoping — useful for confirming intent.
- Environment **required reviewers** gate environment secrets: a job cannot read them until approval, so an environment with no reviewers (or a repo where Actions can auto-approve PRs) is the seam.
- GitHub can be configured to prevent Actions from creating or approving pull requests; where that is off, a workflow that opens and approves its own PR collapses the review gate.
- Dependency review (`actions/dependency-review-action`) compares a PR's dependency changes against vulnerability data — its absence means a merged PR can add a vulnerable action/package unnoticed.
- GitHub publishes SBOMs for its hosted runner images (`actions/runner-images` releases), so a GitHub-hosted runner's preinstalled software is auditable; a self-hosted runner has no such baseline.

### Trusted publishing (OIDC) by registry
- **npm**: trusted publishing requires npm CLI ≥ 11.5.1 and Node ≥ 22.14.0; supported on GitHub Actions, GitLab CI/CD (shared runners), and CircleCI (cloud) — **self-hosted runners are not supported**. The workflow needs `id-token: write`. Provenance is generated automatically for GitHub Actions and GitLab CI/CD (not CircleCI) and **not** for private repositories. Up to 10 trusted publishers per package; existing connections cannot be edited (delete + recreate). "Require 2FA and disallow tokens" shuts the token path; "stage-only" forces `npm stage publish` (maintainer approves with 2FA) instead of direct `npm publish`. `package.json` `repository.url` must exactly match the GitHub repo; `workflow_call`/`workflow_dispatch` validate the *calling* workflow's name.
- **PyPI**: OIDC exchange mints a **short-lived API token valid 15 minutes** — the compromise window is minute-scale versus a long-lived token that lives until manually revoked. Configuring the publisher is the only manual step.

### Runner and cache poisoning
- Privileged triggers (`pull_request_target`, `workflow_run`) share the main branch's cache with other privileged runs; a cache key writable from a less-privileged job is the cross-context seam.
- Artifacts uploaded by an untrusted workflow and consumed by a `workflow_run` workflow must be treated as attacker-controlled; validate content, not just presence.
- Self-hosted runner groups determine blast radius: an enterprise/org-level runner scheduled across repositories lets one workload reach another's environment.

### IaC state / plan
- State files often hold plaintext secrets and resource addresses beyond the reader set; the backend's encryption, locking, and access policy govern the disclosure surface.
- Plan output can echo variables (including secrets) and is frequently published as a CI artifact or PR comment — a PR comment is an unauthorized-reader surface.
- `destroy`/`replace`-shaped operations and `-auto-approve` remove the human gate; a plan from an untrusted fork that can reach apply is the escalation.
- The `sensitive` argument (Terraform ≥ 0.15) redacts CLI/HCP UI output only — values remain in state and plan files, and `terraform output -json`/`-raw` prints them in plaintext.
- `ephemeral` variables/child-module outputs and `ephemeral` blocks (Terraform ≥ 1.10) plus write-only resource arguments with `_wo`/`_wo_version` (Terraform ≥ 1.11) are omitted from state and plan entirely; root-module outputs cannot be ephemeral.
- Backend at-rest encryption examples: HCP Terraform (with customer-supplied keys), S3 backend `encrypt`, GCS customer-supplied/managed keys.

### Build-log / secret leakage (GitLab)
- Masked variables print as `[MASKED]` (sometimes followed by `x` characters); to qualify, a value must be a single line with no spaces, at least 8 characters, and must not collide with a variable name. A value echoed in a transformed form (for example shell-escaped `My\[value\]`) is not masked, and enabling `CI_DEBUG_SERVICES` can reveal values.
- Variable values are encrypted at rest with `aes-256-cbc`; file-type variables avoid `env`/`printenv` dumping a value directly, and masking alone is explicitly described as not a guaranteed control.
- Fork pipelines cannot read the parent project's variables by default, but running a merge-request pipeline **in the parent project** for a fork MR exposes all of them — the merge-request review is the control.
- Variable precedence runs pipeline (run page/schedule/API/upstream) > project > group > instance > dotenv > `.gitlab-ci.yml`; a Developer able to start a pipeline with variables can override a project-level value used by a deploy job unless the minimum-role setting (`ci_pipeline_variables_minimum_override_role`) restricts it.

### Provenance / SLSA
- SLSA is organized into **tracks**; the Build track has L0 (none), L1 (provenance exists, forgeable), L2 (signed provenance generated by a hosted build platform), L3 (hardened build platform that isolates runs and keeps the provenance-signing secret out of user build steps). The current spec version is 1.2 (which also defines a Source track and Verified Properties); the v1.0 build track is the widely-cited reference.
- The productive gap is not "is a signature present" but "does the consumer verify it, and which level does the platform actually meet": an attestation present but unverified by the install path, or an L3 claim where a build step can read the signing key, are the findings.
- `npm publish` from a public repo via trusted publishing attaches provenance by default; the equivalent verification (`npm audit signatures`) is what closes the loop.

### Container build secrets
- Secret **mounts** (`RUN --mount=type=secret,id=...`) expose a secret only for the duration of the `RUN` instruction, at `/run/secrets/<id>` (customizable with `target=`); `env=` mounts it as an environment variable instead. This is the correct pattern.
- Build **args** and **environment variables** persist in the final image and are the wrong way to pass secrets — treat any secret passed as `ARG`/`ENV` as already disclosed in the image history.
- BuildKit supports `GIT_AUTH_TOKEN` (Basic auth with fixed user `x-access-token`, GitHub-style) and `GIT_AUTH_HEADER` (raw `Authorization` value, any provider), with per-host suffixes like `GIT_AUTH_TOKEN.github.com`; `HTTP_AUTH_TOKEN_<host>` / `HTTP_AUTH_HEADER_<host>` cover `COPY`/`ADD` from HTTP hosts. A build that passes these as `--build-arg` instead of `--secret` leaks them into the layer history.
- Verify the pattern against the built image: `docker history` / layer inspection shows a build-arg or `ENV` value but must **not** show a `--mount=type=secret` value (secret mounts are not persisted into layers).

### Reference-integrity incident (tag mutation)
- CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3: `tj-actions/changed-files` (≤ 45.0.7, patched 46.0.1) had **multiple version tags retroactively updated** to a malicious commit that scanned the GitHub Actions Runner Worker process memory and printed secrets into workflow logs, affecting 23,000+ repositories over ~March 14–15, 2025. IoC includes the malicious commit `0e58ed8671d6b60d0890c21b07f8835ace038e67` and unauthorized egress to `gist.githubusercontent.com`. The lesson (SLSA/T1): a tag is not a version; digest pinning is the control.

### Low-cost checks to run first (read-only)
- Resolve every `uses:`/workflow ref to a commit (`git ls-remote` / the API) and compare to the release tag's commit — a mismatch is a finding without executing anything.
- Diff lockfile-vs-manifest resolution for the researcher-owned dependency (`npm ci` then a lockfile-deleted `npm install` in throwaway dirs).
- Confirm provenance/verification on the consumer side (`npm audit signatures` or the equivalent), not just presence on the registry page.
- Grep the workflow for `pull_request_target`/`workflow_run` and for `git checkout`/`actions/checkout` of a fork ref — that pair is the classic pwn-request shape.
- Enumerate trusted publishers and environment reviewer settings against the observed publish workflow; a field mismatch that still publishes is the oracle.
- Decode the OIDC claims from a researcher-owned workflow and diff against the cloud trust policy conditions (watch for `*` wildcards and name-only subjects).
- Map every webhook receiver to its header scheme (GitHub/GitLab/Bitbucket/Stripe) and check whether a timestamp or delivery-ID dedupe exists; a receiver that only compares a body signature cannot see a replay.
- List cache usage per workflow and flag any release/publish job that restores package-manager caches; check the trigger against the default-branch write-capable list.

## References

- [T1 vendor] GitHub Actions, secure use reference (`pull_request_target`/`workflow_run` privilege, SHA pinning, self-hosted runner risk, `::add-mask::`, structured-secret redaction failure, OIDC-to-cloud, audit log): https://docs.github.com/en/actions/reference/security/secure-use
- [T1 vendor] GitHub Actions, securely using `pull_request_target`: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- [T1 vendor] GitHub Actions, event triggers (`pull_request_target`, `workflow_run`): https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- [T1 vendor] GitHub Security Lab, "Preventing pwn requests": https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- [T1 vendor] OpenSSF Scorecard checks (Dangerous-Workflow): https://github.com/ossf/scorecard/blob/main/docs/checks.md
- [T1 vendor] npm, trusted publishing (CLI ≥ 11.5.1 / Node ≥ 22.14.0, providers, `id-token: write`, auto provenance, disallow-tokens, staged publish): https://docs.npmjs.com/trusted-publishers/
- [T1 vendor] PyPI, trusted publishers (OIDC exchange for a 15-minute token): https://docs.pypi.org/trusted-publishers/
- [T1 vendor] SLSA, security levels (Build L0–L3; v1.0 track, current spec v1.2): https://slsa.dev/spec/v1.0/levels
- [T1 vendor] SLSA specification, current version 1.2 (Build and Source tracks, Verified Properties): https://slsa.dev/spec/v1.2/
- [T1 vendor] Docker, build secrets (`--secret`, `RUN --mount=type=secret`, `/run/secrets/<id>`, `GIT_AUTH_TOKEN`/`GIT_AUTH_HEADER`, `HTTP_AUTH_TOKEN_<host>`): https://docs.docker.com/build/building/secrets/
- [T3 vuln intel] CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3, `tj-actions/changed-files` tag mutation exfiltrating runner memory to logs (affected ≤ 45.0.7, patched 46.0.1, 23k+ repos): https://github.com/advisories/GHSA-mrrh-fwg8-r2c3
- [T3 vuln intel] CVE-2025-30066 at NVD (same incident, canonical ID): https://nvd.nist.gov/vuln/detail/CVE-2025-30066
- [T1 vendor] CISA alert, supply-chain compromise of a third-party GitHub Action (CVE-2025-30066): https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- [T1 vendor] OpenSSF Trusted Publishers specification (cross-registry OIDC publisher model): https://repos.openssf.org/trusted-publishers-for-all-package-repositories
- [T1 vendor] SLSA requirements (prescriptive per-level requirements, verification guidance): https://slsa.dev/spec/v1.0/requirements
- [T1 vendor] SLSA/Sigstore keyless signing in Kubernetes 2026: https://www.hams.tech/blog/kubernetes-supply-chain-security-sigstore-slsa-2026.html ; DevSecOps playbook: https://cloudaware.com/blog/devsecops-kubernetes/
- [T2 research] Dependency confusion namespace-takeover story: https://medium.com/@sakshirathore3478/dependency-confusion-a-namespace-takeover-story-fa334533bd50
- [T0 standards] SLSA framework and Sigstore documentation for provenance and signing semantics
- [T1 vendor] OWASP software supply-chain and CI-CD security guidance for the observed pipeline shape
- [T1 vendor] Package-manager documentation for the observed registry and feed priority behavior
- [T1 vendor] CI platform documentation for fork builds, secret scoping, environments, and required workflows
- [T2 research] parsers-injection/parsers.md for manifest and lockfile parsing differentials reused here
- [T1 vendor] GitHub, validating webhook deliveries (`X-Hub-Signature-256`, HMAC hex digest, `sha256=` prefix, constant-time compare, absent header when no secret, test vectors): https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- [T1 vendor] GitHub, webhook events and payloads (delivery headers incl. `X-GitHub-Delivery` GUID, `X-GitHub-Hook-ID`, `X-GitHub-Event`): https://docs.github.com/en/webhooks/webhook-events-and-payloads
- [T1 vendor] GitLab, webhooks (signing token vs. legacy `X-Gitlab-Token`, Standard Webhooks headers, HMAC-SHA256 over `{message_id}.{timestamp}.{body}`, timestamp-freshness replay guidance): https://docs.gitlab.com/user/project/integrations/webhooks/
- [T1 vendor] Atlassian, Bitbucket Cloud webhooks (secret token, `X-Hub-Signature` `method=signature` WebSub format, verbatim body, method may change): https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/
- [T1 vendor] Stripe, resolving webhook signature verification errors (`Stripe-Signature` `t=,v1=,v0=`, `constructEvent` raw-body requirement, framework body mutation): https://docs.stripe.com/webhooks/signature
- [T1 vendor] stripe-node source, `DEFAULT_TOLERANCE: 300`, `verifyHeader` default tolerance `0`, header parsing of multiple `v1` signatures: https://raw.githubusercontent.com/stripe/stripe-node/master/src/Webhooks.ts
- [T1 vendor] GitHub, OpenID Connect reference (`sub`/`job_workflow_ref`/`repo_property_*` claims, immutable subject claims from July 15 2026, Dependabot `event_name: dynamic`): https://docs.github.com/en/actions/reference/security/oidc
- [T1 vendor] GitHub, configuring OIDC in AWS (`sub` condition, wildcard `repo:org/repo:*` covering any branch/PR/environment, no custom claims in AWS): https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws
- [T1 vendor] GitLab, OIDC ID token authentication (`sub` format and configuration, path-recycling block, claim list, AWS condition keys, token lifetime): https://docs.gitlab.com/ci/secrets/id_token_authentication/
- [T1 vendor] GitHub, dependency caching reference (cache scope and restore order, low-trust trigger read-only cache access, write-capable trigger list, caches not signed): https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching
- [T1 vendor] GitHub changelog, read-only Actions cache for untrusted triggers (June 26, 2026): https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/
- [T2 research] Adnan Khan, "Cacheract: The Monster in your Build Cache" (cache-native persistence, cache stuffing, release-job cache poisoning, provenance still verifying): https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/
- [T1 vendor] GitHub CodeQL query help, actions/cache-poisoning/direct-cache (severity 7.5, write-capable default-branch triggers): https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/
- [T1 vendor] npm, generating provenance statements (Sigstore attestations, supported providers, `npm audit signatures`, `package-manager-cache: false` in release builds): https://docs.npmjs.com/generating-provenance-statements
- [T1 vendor] GitHub, artifact attestations concepts (SLSA v1.0 Build L2, L3 with reusable workflows, public vs private Sigstore instances, `gh attestation verify`): https://docs.github.com/en/actions/concepts/security/artifact-attestations
- [T1 vendor] npm, scope (scope ownership, `@scope:registry` association, scoped install/publish routing): https://docs.npmjs.com/cli/v10/using-npm/scope
- [T1 vendor] pip, secure installs (`--require-hashes` all-or-nothing, remote hash fragments do not satisfy it, `--only-binary :all:`): https://pip.pypa.io/en/stable/topics/secure-installs/
- [T0 standards] PEP 708, extending the Repository API to mitigate dependency confusion (rejected April 2026; multi-repository namespace flattening and best-match resolution): https://peps.python.org/pep-0708/
- [T0 standards] PEP 503, simple repository API (normalized names: lowercase, runs of `.`/`-`/`_` collapse to `-`): https://peps.python.org/pep-0503/
- [T1 vendor] NuGet, package source mapping (NuGet 6.0, `<packageSourceMapping>` patterns and precedence, transitive coverage, query/global-folder gaps): https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- [T1 vendor] HashiCorp, manage sensitive data in Terraform (`sensitive` redaction only, ephemeral/write-only omission from state and plan, `terraform output -json/-raw`, backend encryption): https://developer.hashicorp.com/terraform/language/manage-sensitive-data
- [T1 vendor] GitLab, CI/CD variables (masked-variable requirements and limitations, fork pipeline variable access, precedence order, encryption at rest): https://docs.gitlab.com/ci/variables/
