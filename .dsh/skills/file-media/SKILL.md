---
name: file-media
description: "File upload, processing, preview, download, share, and version surfaces; representation bypass, stale share-link survival, disposition and type confusion, metadata reflection, and cache persistence."
---

# File / Media

The primary path and every derived representation must agree: preview, thumbnail, version, text-extract, archive entry, and share URL are the same object and deserve the same authorization. Proof is a **representation sweep** of researcher-controlled files across sessions, plus a **read-back** of hashes and canaries after each **lifecycle** transition.

## Run this

1. **Baseline every representation at upload** — upload one benign researcher file per type; record status, stored URL, preview URL, headers, body hash, and share-URL shape. Done when each representation has an owner, second-account, logged-out, and anonymous baseline.

2. **Run the representation sweep** — request original, preview, thumbnail, text-extract, version, and export variants from every session and diff status and hashes. Done when each (representation × session) pair has an observed result.

3. **Walk the lifecycle in order** — downgrade permission, expire, revoke, then delete the researcher object, re-requesting every known URL from a clean session after each transition. Done when each transition has a post-change read-back naming the URL tested.

4. **Perturb one type signal per request** — extension, content-type header, or magic bytes, with inert content, watching for validator-versus-renderer disagreement. Done when each signal has one controlled probe and its observed disagreement or agreement.

5. **Probe archives with one canary entry pair** — a single traversal-named and one link-shaped entry containing canary text; verify listing and extraction read-back. Done when extraction is confirmed inside the researcher directory only.

6. **Attribute only the researcher canary** — matching bytes or canary text in a non-owner session is the oracle; a 200, a login page, or a header alone is not.

## Done when

- Every (representation × session) pair holds a recorded status and body hash.

- Every lifecycle transition has a post-change read-back from a clean session.

- Every bypass claim carries researcher file bytes or canary text outside the owner session.

## Stop conditions

- A non-researcher file is returned — halt, record the oracle, and report the class without fetching further objects.

- A stored script executes outside the researcher session — stop, delete the researcher files, and report the renderer sink and oracle.

- Scanner or renderer slowdown, or third-party cache pollution — halt, clean up researcher artifacts, and report the oracle with the cleanup record.

## Depth

Field guide: `12_knowledge/file-media/file-media.md` — research families, oracle catalog, false positives, and archive, parser, signed-URL, and CDN version notes.
