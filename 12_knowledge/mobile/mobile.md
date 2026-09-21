# Mobile / Client Applications

> SCOPE: Load when an in-scope iOS, Android, or companion client reveals API hosts, routes, flows, or trust assumptions; server-side impact on researcher accounts is still required.

## Research families

- API host, version, and router discovery from bundles, traffic, and configs
- Hidden routes, parameters, feature flags, and staged endpoints in client code
- Authentication-flow differentials (mobile versus web session, token, refresh handling)
- Deep, universal, and custom-scheme link routing with parameter trust
- Embedded webview bridge, origin, and message-passing trust
- Client-side authorization or hiding that the server does not re-enforce
- Local and offline state replayed against the server after permission change
- Protocol-format differentials (mobile-only verbs, versions, encodings, serializers)
- Push, sync, and companion-channel subscription and injection context
- Build, certificate-pinning, and update-channel observations as supporting signals
- Custom-scheme deep-link collision (unverified scheme claimed by another installed app)
- Exported Android components (activities, services, receivers, content providers) reachable by external intents
- WebView JavaScript bridges (`addJavascriptInterface`) and navigation-callback trust
- Universal-link / app-link association misconfiguration (missing or wrong association file, redirects, wildcard hosts)
- Transport hardening posture that changes server trust (cleartext defaults, debug trust anchors, pin expiry)
- Backup and local-storage channels (Android backup, iOS backup, keychain accessibility) as data-exposure seams
- Mobile-only encoder/serializer differences (client sends a shape the web path never produces, reaching a laxer server branch)
- Update / force-upgrade bypass (an old build kept alive to reach the legacy server contract)
- Bundled-SDK request surface (parameters or headers only a third-party SDK sends reaching a laxer server branch)
- Mobile-only session-establishment flow (device registration, biometrics, or push-token binding that the web flow lacks)
- Clipboard / share-sheet / screenshot exposure of researcher records (server oracle required before it counts)
- Intent redirection (nested or serialized intent in extras, or a string parsed via `Intent.parseUri`, launched in the app's context)
- PendingIntent-based privilege reuse (mutable base intent, implicit target, `FLAG_GRANT_*` leakage)
- Service/receiver IPC (bound services, AIDL/Messenger, registered receivers, sticky broadcasts)
- iOS app-group / App-Extension shared container and keychain access-group trust
- Device-attestation verdicts (Play Integrity, App Attest) as gates the server may or may not be enforcing
- Pasteboard programming changes (iOS 16 paste approval, Android 13 preview/`EXTRA_IS_SENSITIVE`)

## Preconditions

- The mobile or client target is explicitly in scope; companion binaries are intelligence sources, not standalone proof.
- Researcher-controlled accounts, devices or emulators, and interceptable test traffic the program permits; respect platform and jailbreak or root restrictions.
- Baseline of web-versus-mobile behavior for the same researcher workflow before claiming a mobile-only gap.
- Deep-link and webview hypotheses tied to an observed handler, bridge method, or server endpoint — not a speculative scheme.
- Any client-visible secret, flag, or endpoint treated as a lead until it produces a server-side oracle on researcher data.
- Server-side impact required; client-side exposure alone never becomes a finding in this pack.
- For app-link/universal-link probes: a researcher-controlled or observed HTTPS host and its association file (or its absence) recorded before crafting the link.
- For exported-component probes: the component's `exported`/intent-filter declaration observed in the manifest, not assumed.
- For pinning/cleartext observations: the app's transport config (or platform default) identified for the specific API level.
- For webview probes: the exact bridge method names and the origins the WebView is allowed to load recorded from the binary.
- For offline-replay probes: a queued operation captured while authenticated and a revocation/downgrade event available on researcher data.
- For SDK-surface probes: the observed requests attributable to a bundled SDK separated from first-party calls.
- For session-flow probes: the mobile-specific registration / biometric / push-token step mapped to its server endpoint.
- For intent-redirection probes: the nested-intent key name, the sink (`startActivity`/`startService`/`bindService`), and the target component recorded; the probe stays on researcher accounts.
- For IPC probes: the interface descriptor/action and the declared `android:permission`/`protectionLevel` (or its absence) read from the manifest or service dump before binding.
- For storage/backup probes: the manifest storage attributes (`allowBackup`, `fullBackupContent`, `dataExtractionRules`, `backupAgent`) recorded, plus whether the build is `android:debuggable="true"` (required for `adb backup`).
- For keychain/keystore probes: the accessibility attribute (`kSecAttrAccessible*`) or key authorization (`setUserAuthenticationParameters`, `setIsStrongBoxBacked`) observed, not inferred from behavior.
- For pasteboard/clipboard probes: the OS version recorded, because user-approval and preview behavior changed at iOS 16 and Android 13.
- For attestation-gated flows: whether the server consumes the verdict (Play Integrity `deviceRecognitionVerdict`, App Attest assertion) or merely displays it.

## Oracles

- Hidden-route authorization gap: client-mined route returns researcher-hidden records or state changes where the documented web path denies.
- Version differential: legacy or mobile-only API version honors the same researcher request the current web version denies.
- Parameter acceptance gap: hidden or flagged parameter mutates researcher state through the mobile API while the web path ignores or rejects it.
- Deep-link trust confirmation: crafted link with researcher data opens a privileged screen or triggers a server action in the researcher session without the expected check.
- Webview-bridge execution: researcher message to an observed bridge method reads or writes researcher account state across the expected origin boundary.
- Offline-replay persistence: queued researcher action captured offline still applies after permission downgrade, revocation, or logout when replayed.
- Token-scope gap: mobile-issued token reaches an admin, cross-account, or cross-tenant researcher endpoint the web-issued token cannot.
- Push or sync injection: researcher-crafted sync payload or subscription produces another researcher session's event, record, or notification it should not receive.
- Custom-scheme collision: a researcher-installed second app handles a link intended for the target app's custom scheme, delivering attacker-chosen parameters to the same handler.
- Exported-component reach: an external intent starts a non-exported-intended activity, service, receiver, or provider and returns or mutates researcher data.
- Association downgrade: a universal/app link whose association file is missing, served with a redirect, or wildcarded falls back to the browser or to an attacker-declared handler.
- Cleartext/trust-anchor gap: server accepts a request the app only, by config, sends in cleartext or to a debug-only trust anchor, exposing a mobile-only trust assumption.
- Bridge reachability: any page the WebView can load (or redirect to) can invoke an exported `@JavascriptInterface` method, not just the app's own origin.
- Legacy-contract bypass: an old client build reaches a deprecated endpoint that skips a control the current build enforces.
- Backup-restore leak: a restored researcher backup exposes a token, cache, or record the served session would scope out.
- Force-upgrade bypass: an old build persists past the version gate and reaches data the current client is denied.
- SDK-parameter acceptance: a parameter or header only a bundled SDK sends reaches a server branch the app UI cannot.
- Device-flow gap: the mobile-only registration / biometric / push-token step authorizes an action the web flow gates.
- Intent-redirection reach: a researcher-supplied nested intent (extra or serialized string) starts an unexported component or private provider in the app's security context, returning data or changing state.
- PendingIntent reuse: researcher app fills or redirects a mutable `PendingIntent` whose base intent is implicit, reaching the app's granted URI or component.
- Grant leakage: a `FLAG_GRANT_READ/WRITE_URI_PERMISSION` on a forwarded intent survives into the researcher app and reads the app's private provider.
- Receiver/service exposure: an unprotected exported receiver or bound service returns researcher-scoped data or performs a privileged mutation when triggered from a researcher app.
- Provider path traversal: a `content://` URI with traversal segments (`../`) in the path or in an open-file call returns a file outside the provider's intended directory.
- WebView file-origin relaxation: with `allowFileAccess` + `allowFileAccessFromFileURLs`/`allowUniversalAccessFromFileURLs` enabled, researcher-controlled HTML loaded from `file://` reads app-private files and posts them out.
- WebMessage origin gap: a `WebMessageListener`/`postWebMessage` flow accepts a message from an origin outside the declared `allowedOriginRules`, or trusts `getUrl()` instead of the callback origin.
- Backup-inclusion of secrets: an Auto Backup / `bmgr` restore of the researcher device brings back a token, cookie, or record that the server would not re-issue to that session.
- Keychain migration: a keychain item without the `ThisDeviceOnly` suffix restores onto a different researcher device and still authenticates — or the server accepts a key/assertion that should be device-bound.
- Pasteboard bypass: a researcher app reads the target app's pasteboard content without the OS approval UI appearing (own-app read, non-user-initiated paste, or a custom paste path).
- Clipboard-read signal: the target app reads the system clipboard and the OS toast (“APP pasted from your clipboard”) is or is not shown for the observed principal/version pair.

## Minimal safe proof

1. Baseline: perform the same researcher workflow on web and on mobile; record hosts, versions, routes, tokens, and allow versus deny decisions per session.
2. Mine and track: extract candidate hosts, routes, flags, and link schemes from the client; record each as a hypothesis with its source location before sending traffic.
3. Single-variable replay: replay one mined route, version, or parameter through the observed mobile API from both researcher sessions with one field changed; diff against the web baseline.
4. Link and bridge check: deliver one crafted deep link and one bridge-shaped message containing researcher canaries to the researcher device only; observe handler and server effect.
5. Lifecycle replay: queue one researcher-state change offline, downgrade or revoke the permission, reconnect, and verify whether the server still applies it; restore state after.
6. IPC probe: send one externally-crafted intent or bind to the observed interface on the researcher device with a canary value; record which component answered and what it returned before claiming reach.
7. Storage probe: take a researcher-device backup (or read the keychain/keystore item) and check for exactly one canary credential; never exfiltrate real secrets, and stop at the canary.
8. Attestation probe: request the integrity verdict for the researcher device and record which labels or assertions the server actually consumes for one gated action.
9. Stop conditions: any non-researcher account effect, production push or sync disturbance, auth-token disclosure beyond the researcher device, or platform-restriction conflict — halt, clean up, and report the server oracle only.

## False positives

- Client-visible endpoint, key, or flag with no server-side authorization gap — bundled configuration is not access-control failure; require a researcher-data oracle.
- Hardcoded public API key restricted by bundle ID, quota, or server policy — key presence without cross-account researcher access is platform context.
- Deep link opening a public screen with researcher-safe defaults — handler reachability without privileged data or action is intended routing.
- Webview rendering researcher content within the expected origin and sandbox — rendering alone is not bridge bypass; require cross-boundary read or write.
- Mobile-only error text naming internal hosts or versions — diagnostic disclosure without researcher-record access is hardening context.
- Offline queue applying a still-authorized researcher action after reconnect — expected sync, not replay bypass; require post-revocation or post-downgrade application.
- Certificate-pinning or root-detection absence alone — platform hardening posture without a server-side impact is not a bounty finding in most programs.
- Traffic difference caused by caching, staged rollout, or account cohort — confirm with flag-fixed, cache-cleared repeats before claiming a version gap.
- App-link disambiguation dialog *not* appearing for a verified link — that is the intended behaviour of verified App Links, not a bypass.
- Custom scheme shared with a sibling first-party app on the same device set — collision is expected routing, not a finding; require attacker-controlled parameters reaching a privileged server action.
- Debug trust anchors trusted on a genuinely debuggable build only — the `debug-overrides` path is correct unless it applies to a release (`android:debuggable="false"`) build.
- Cleartext permitted only to a localhost/dev host — not sensitive-host exposure; require a production or secret-bearing host.
- Exported component in the manifest but with no reachable sensitive action — `exported="true"` alone is platform context; require a data read/write or state change on researcher data.
- WebView loading your own host with JavaScript enabled but no bridge exposed — rendering is not a bridge oracle; require a call into app code or a cross-boundary read.
- Backup file containing only data the device owner already possesses — local exposure without a server-side cross-account oracle is not a finding in this pack.
- Intent redirection that only reaches a component the researcher app could already start explicitly — no privilege gain; require access to a component or provider the researcher app cannot reach directly.
- `getCallingActivity()` returning the researcher's own activity — the check works for result flows; the documented weakness is that a malicious sender can pass `null`, so a null accepting branch, not the API's existence, is the bug.
- `FLAG_MUTABLE` on a PendingIntent with an explicit component — mutability alone is not the issue; require an implicit base intent or a grant the sender should not receive.
- WebView `file:///android_asset` and `file:///android_res` reads — these are always allowed regardless of file-access settings and are app-packaged content, not private data.
- `setAllowContentAccess(true)` default — enabled since API 16 by design; require a provider reachable through the WebView that returns data the principal should not see.
- iOS paste approval alert *not* shown because the app read its own pasteboard, or because the paste came from a `UIPasteControl` — user-initiated paste is the documented prompt-free path.
- Android 13 clipboard preview appearing for content the app did not flag sensitive — the preview is default system behavior; require sensitive data exposed because `EXTRA_IS_SENSITIVE` was not set on the app's own copy path.
- App Attest `isSupported == false` or Play Integrity `UNEVALUATED` — graceful fallback is documented guidance, not by itself a server-authz gap; require the downgraded path to reach privileged data.
- Root/jailbreak detection signals present in the binary but never enforced server-side — resilience library presence is not an oracle; require a server-side decision that trusts or rejects the signal.

## Version/implementation notes

### Android deep links and App Links

- Two link types: **custom URL schemes** (`myapp://`) are *any* scheme and are **not verified by the OS**; **Android App Links** use `http://`/`https://` plus the `autoVerify` attribute and are OS-verified (Android 6.0, API 23+). [T1 OWASP MASTG]
- **Deep-link collision**: because custom schemes are unverified, any installed app can declare the same intent filter and the system shows a **disambiguation dialog** — a user can pick a malicious app. Android 12 (API 31)+ additionally resolves a generic web intent to the user's **default browser** unless the target app is approved for the specific domain. [T1 OWASP MASTG]
- **Android gives no built-in caller identity** for an incoming intent (unlike iOS's `sourceApplication`): any app on the device can send an intent matching an exported filter — the root of exported-component and scheme-collision risk. [T1 OWASP MASTG]
- **App Link verification**: `android:autoVerify="true"` makes the install query each declared host's Digital Asset Links file at `https://<host>/.well-known/assetlinks.json`, which must be served over **HTTPS** and list the app's package name and signing-certificate fingerprint. A server-side **redirect** (http→https, or `example.com`→`www.example.com`) stops verification. **Each host, including every subdomain, needs its own file**; a wildcard `*.example.com` verifies against the root-domain file. [T1 Android] [T1 OWASP MASTG]
- Verification timing/behaviour shift by version: on **Android 11 (API 30) and lower**, a matching file must exist for **all** hosts in the manifest and a single non-verifiable link can skip verification for *all* App Links (all-or-nothing). From **Android 15 (API 35)**, the system re-verifies periodically and `assetlinks.json` changes can take **up to seven days** to propagate (Android 14 and lower only pick changes up on install/update). [T1 Android]
- Device inspection commands: `adb shell pm get-app-links <pkg>`, `adb shell pm verify-app-links --re-verify <pkg>`, `adb shell pm set-app-links --package <pkg> 0 all`, `adb shell am compat enable 175408749 <pkg>`, and `am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "https://host"`. [T1 Android]
- Manifest shape to enumerate: an `<intent-filter>` combining `android.intent.action.VIEW`, `android.intent.category.DEFAULT`, `android.intent.category.BROWSABLE`, and `<data>` elements (scheme/host/path); `<data>` elements inside one filter are merged across attribute combinations. [T1 OWASP MASTG]

Platform link-handling comparison:

| Aspect | Android custom scheme | Android App Link | iOS custom scheme | iOS Universal Link |
|---|---|---|---|---|
| Scheme | any (`myapp://`) | `http`/`https` only | any | `http`/`https` only |
| OS verification | none | `.well-known/assetlinks.json` | none | `apple-app-site-association` |
| Caller identity available | partial — `getCallingPackage()`/`getCallingActivity()` may be `null`; never an authz control | same as custom scheme: intent senders are unauthenticated | partial — `sourceApplication` only when the sender is on the same team, `nil` otherwise [T1 Apple] | no reliable sender identity |
| Claimable by other apps | yes (collision/dialog) | no | yes | no |

### Android intents, exported components, and IPC surfaces

- **Intent redirection** is defined as an attacker controlling part or all of the contents of an intent that a vulnerable app then launches: the intent arrives as a serialized extra or a marshaled string (e.g. `Intent.parseUri`), and the app starts it with `startActivity`/`startService`/`bindService`. Impact ranges from executing internal features to reaching private components such as unexported `ContentProvider`s. [T1 Android intent redirection]
- Mitigations that reveal what to test for: sanitize nested intents (`IntentSanitizer`), **check or clear** `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, `FLAG_GRANT_PREFIX_URI_PERMISSION`, verify the resolved destination (`resolveActivity`, comparing package and class), or use an immutable `PendingIntent`. [T1 Android intent redirection]
- Documented false checks to look for: code that trusts `getCallingActivity()` to be non-null (a malicious app can pass `null`) or that assumes `checkCallingPermission()` throws instead of returning a value. [T1 Android intent redirection]
- **Android 16** adds by-default launch hardening for intent-redirection exploits; apps can opt out with `Intent.removeLaunchSecurityProtection()` on a nested intent. **Android 15** adds `StrictMode.detectUnsafeIntentLaunch()`; for target API 31+ the system flags an unsafe launch when the app unparcels a nested intent from extras and immediately passes it to `startActivity`/`startService`/`bindService`. [T1 Android intent redirection] [T1 Android 15]
- **Android 12**: `android:exported` must be declared explicitly for every component with an intent filter. The manifest reference states the default is `false` when there are no intent filters, so a filter-bearing component without the attribute is the pre-12 pattern that silently exposed it; `android:exported="false"` makes external starts throw `ActivityNotFoundException`. [T1 Android 12] [T1 Android manifest]
- **Android 14 (target API 34+)** tightened intents and receivers: implicit intents are delivered **only to exported components** (explicit intents are required for unexported ones); creating a **mutable `PendingIntent` whose base intent names neither component nor package throws**; context-registered receivers must pass `RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED` (system-broadcast-only registrations exempt). [T1 Android 14]
- **PendingIntent testing** (MASTG-TEST-0030, deprecated in favor of MASTG v2): the base intent must be immutable and name the exact package, action, and component; the classic failure is CVE-2020-0389 / A-156959408, where an implicit `ACTION_VIEW` base intent combined with a mutable `PendingIntent` made the notification action redirectable. API entry points to enumerate: `getActivity`, `getActivities`, `getService`, `getForegroundService`. [T1 OWASP MASTG]
- **Implicit-intent results** (MASTG-TEST-0026): an app that consumes the result of `startActivityForResult` (e.g. `GET_CONTENT`, `PICK`, `IMAGE_CAPTURE`) without validating the returned URI can be made to read arbitrary files from its own `/data/data/<pkg>` when the researcher app supplies a `content://`/`file://` URI; copies written to `getExternalCacheDir()`/`getExternalFilesDir()` are then readable by other apps. [T1 OWASP MASTG]
- **IPC enumeration**: exported activities/services/receivers, content providers (`android:exported`, `android:grantUriPermissions`, `android:permission` plus `protectionLevel`), bound services with AIDL/Messenger interfaces, and context-registered receivers. Android's own risk index groups these under MASVS-PLATFORM (`Content resolvers`, `Implicit Intent hijacking`, `Insecure broadcast receivers`, `Intent redirection`, `Permission-based access control to exported components`, `Pending Intents`, `Sticky Broadcasts`, `StrandHogg Attack / Task Affinity`, `Tapjacking`, `Unsafe use of deep links`, `WebView – Native bridges`, `android:debuggable`, `android:exported`). [T1 Android risks]

### Android WebView: bridges, file access, and storage

- **WebView**: JavaScript is **disabled by default** (`setJavaScriptEnabled(true)` to opt in). [`addJavascriptInterface`](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)) lets page JavaScript call into app code and is explicitly documented as dangerous when the HTML is untrusted; from `targetSdkVersion` 17 the exposed method must be `public` and annotated `@JavascriptInterface`. [T1 Android]
- Navigation trust: override `shouldOverrideUrlLoading` to keep only your own host in the WebView and launch foreign links externally, and understand that `WebView` only fires the callback for **valid** URLs (a bare `showProfile` link may not reach it, inconsistently). Use a well-formed custom scheme (`example-app:...`) or an HTTPS URL you control. `setSupportMultipleWindows(true)` **without** overriding `onCreateWindow` prevents `target="_blank"` popups. [T1 Android]
- **Bridge mechanisms differ in origin safety**: `addWebMessageListener` (AndroidX WebKit) is allowlist-based — the injected proxy is exposed only to origins matching `allowedOriginRules`, and callbacks expose sender origin, main-frame status, and a reply proxy; `postWebMessage` is origin-aware and main-frame limited (URI constraints apply to `data:`/`file:`/`loadData()` unless the target origin is `*`); `addJavascriptInterface` is the legacy synchronous model available to **every frame including iframes**, with **no origin-based access control**, and `WebView.getUrl()` is not suitable for identifying the invoking frame. Before API 21, injected objects were reachable by reflection (`getClass().forName('java.lang.Runtime')...`). [T1 OWASP MASTG]
- **File-access settings and their defaults** (assets/resources via `file:///android_asset`, `file:///android_res` are always allowed regardless): `setAllowFileAccess` default **true ≤ API 29 / false ≥ API 30**; `setAllowFileAccessFromFileURLs` default **true ≤ API 15 / false ≥ API 16** (deprecated in API 30); `setAllowUniversalAccessFromFileURLs` default **true ≤ API 15 / false ≥ API 16** (deprecated in API 30). Modern apps that enable them get `file://` pages reading other `file://` URLs, and `content://`/`file://` XHR unless the Fetch API is used. [T1 Android WebSettings] [T1 OWASP MASTG]
- Documented impact wording to reuse in a report: enabling universal access “allows malicious scripts loaded in a `file://` context to launch cross-site scripting attacks, either accessing arbitrary local files including WebView cookies, app private data or even credentials used on arbitrary web sites.” Recommended replacement is `androidx.webkit.WebViewAssetLoader` with `https://` URLs via a `WebViewClient`; if `file://` must be used, explicitly set all three to `false`. [T1 Android WebSettings] [T1 OWASP MASTG BEST-0011]
- **`content://` access**: `setAllowContentAccess` is enabled by default (API 16+); a WebView can reach providers the app itself can reach, exported or not, and exported providers of other apps. `content://` pages can iframe other `content://` pages but the parent cannot read into the iframe, and non-`content://` pages cannot load `content://` iframes or subresources unless the file-origin relaxations above are on. [T1 OWASP MASTG]
- **Default navigation behavior**: without a `WebViewClient`, navigation is handed to the system browser (no shared cookies or JS bindings), so assigning a `WebViewClient` is the worst-case configuration and requires allowlist validation in `shouldOverrideUrlLoading` and/or `shouldInterceptRequest`. Safe Browsing is available from Android 8.1 (API 27) for known-threat URLs. [T1 OWASP MASTG]
- **WebView storage lives per app** under `/data/data/<pkg>/app_webview/`: HTTP cache, DOM storage, IndexedDB, cookies, and OPFS/SQLite-Wasm files. `WebView.clearCache(true)`, `WebStorage.deleteAllData()`, and `CookieManager.removeAllCookies()` do **not** cover IndexedDB/OPFS; wiping those requires clearing the whole WebView profile, which the app cannot do without clearing all app data. [T1 OWASP MASTG]

| Surface | API | Trust note |
|---|---|---|
| JS engine | `WebSettings.setJavaScriptEnabled` | off by default; enabling widens reach |
| Native bridge | `addJavascriptInterface` + `@JavascriptInterface` | any loadable page can call exposed methods; every frame |
| Message bridge | `addWebMessageListener` / `postWebMessage` | origin allowlist; prefer over `addJavascriptInterface` |
| Navigation | `WebViewClient.shouldOverrideUrlLoading` | only valid URLs trigger it; must pin host |
| Windows | `setSupportMultipleWindows` + `onCreateWindow` | multiple windows off unless overridden |
| Content loading | `loadData` / `loadDataWithBaseURL` | base URL governs origin of loaded content |
| File access | `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` | relaxed `file://` origin = private-file read + XSS |
| Provider access | `setAllowContentAccess` | on by default; reaches the app's own providers |

### Android transport and WebView hardening

- **Network security configuration** (`android:networkSecurityConfig` XML in the manifest) governs trust per app/domain. Defaults that change server trust: **cleartext is enabled by default up to API 27 and disabled from API 28**; apps targeting **API 23 and lower also trust user-added CAs** by default; `debug-overrides` trust anchors apply **only** when `android:debuggable="true"`; `<certificates src="user" overridePins="true">` bypasses pinning (default in `debug-overrides`). [T1 Android]
- **Certificate pinning** is declared per domain as `<pin-set expiration="yyyy-MM-dd">` containing `<pin digest="SHA-256">base64(SPKI)</pin>` — **only SHA-256** is supported, a chain is valid if it contains at least one pinned key, and a **backup pin** is recommended. A pin **expiration** disables pinning after that date, which is a deliberate connectivity trade-off that also lowers the bar for an on-path attacker post-expiry. [T1 Android]
- Newer transport knobs are API-gated: **Certificate Transparency** is available from **API 36** (off by default, opt-in; **API 37** default on, opt-out) and **Encrypted Client Hello (ECH)** is **API 37+**. Localhost gets an implicit config from **API 37** (cleartext allowed, CT/pinning not enforced). [T1 Android]

Network-config defaults and their security effect:

| Target API level | Cleartext default | User CA trusted by default | Debug anchors |
|---|---|---|---|
| ≤ 23 | permitted | yes | n/a |
| 24–27 | permitted | no | applied when `android:debuggable="true"` |
| ≥ 28 | **blocked** | no | applied when `android:debuggable="true"` |

### Android storage: Auto Backup and Keystore

- **Auto Backup** is on by default for apps targeting API 23+ (`android:allowBackup` default `true`) and covers almost all app data. From **API 31+**, `allowBackup="false"` disables cloud backup but **not** device-to-device transfer on some manufacturer devices; rules moved from `android:fullBackupContent`/`backup_rules.xml` (≤ Android 11) to `android:dataExtractionRules`/`data_extraction_rules.xml` (Android 12+) with separate `<cloud-backup>`, `<device-transfer>`, and — **Android 16 QPR2** onwards — `<cross-platform-transfer>` sections. `<cloud-backup disableIfNoEncryptionCapabilities="true">` keeps data out of the cloud when the device cannot encrypt, while D2D transfers continue. [T1 Android autobackup] [T1 OWASP MASTG]
- **Testing backup exposure**: `adb backup` is **restricted since Android 12 and requires `android:debuggable="true"`**; the current path is Backup Manager (`adb shell bmgr`), whose local transport writes one `.ab` TAR per app under `/data/data/com.android.localtransport/files/`. The v2 check (MASTG-TEST-0262) fails an app when `allowBackup` is true (or absent) and neither `backup_rules.xml` nor `data_extraction_rules.xml` excludes its sensitive files. [T1 OWASP MASTG TECH-0128] [T1 OWASP MASTG TEST-0262]
- **Keystore guarantees** (`AndroidKeyStore`, API 18+): key material never enters the app process and can be bound to TEE/StrongBox; Android 9 (API 28) adds **StrongBox KeyMint** (own CPU, secure storage, TRNG, tamper resistance) and encrypted-key import. For API 29+ check `KeyInfo.getSecurityLevel()` (`TRUSTED_ENVIRONMENT` or `STRONGBOX` means secure hardware); for API ≤ 28 check `KeyInfo.isInsideSecurityHardware()`. Keys can be bound to user authentication (`setUserAuthenticationParameters`) and invalidated by biometric enrolment (`setInvalidatedByBiometricEnrollment`). [T1 Android keystore]
- Oracle framing for storage work: a keystore/keychain item is only interesting server-side when the server accepts a token, signature, or assertion that the platform would not have produced for that principal/device — device binding that is asked for but not verified is the gap. [T1 Android keystore] [T1 Apple App Attest]

### iOS Universal Links, custom schemes, and ATS

- Universal links are backed by an `apple-app-site-association` file (no extension) served over **HTTPS without redirects** at `https://<domain>/apple-app-site-association` **or** `https://<domain>/.well-known/apple-app-site-association`, plus a `com.apple.developer.associated-domains` entitlement entry prefixed `applinks:`. On iOS 9+ the file may be unsigned with `Content-Type: application/json`; uncompressed size ≤ **128 KB** (iOS 9.3.1+). [T1 Apple]
- The file's `applinks` block maps `appID` (team-ID + bundle-ID) to a `paths` array; `*` matches a substring, `?` a single character, a `NOT ` prefix excludes an area, matching is **case-sensitive**, order matters (first match wins), and **only the path component** is compared (query and fragment ignored). Wildcard entries like `*.mywebsite.com` do **not** match the bare `mywebsite.com` — each needs its own entry. [T1 Apple]
- Current Apple guidance uses `components` instead of `paths`: each entry is a dictionary with `/`, `?`, and `#` pattern keys plus optional `"exclude": true`, and patterns support `*` (e.g. `{"/": "/buy/*"}`, `{"/": "/help/*", "?": {"articleNumber": "????"}}`, `{"#": "no_universal_links", "exclude": true}`). Every subdomain needs its own entitlement entry and its own association file. [T1 Apple associated domains]
- **Association delivery changed**: from macOS 11 and iOS 14, apps no longer fetch `apple-app-site-association` directly — requests go to an Apple-managed CDN that refreshes the file within **24 hours**, and devices check for updates **about once per week** after install. A private/development server can bypass the CDN with an alternate mode (`<service>:<domain>?mode=developer`). This is why a freshly-fixed association file can keep failing (or keep working after a mistake) for days. [T1 Apple associated domains]
- Security contrast to state explicitly: **custom URL schemes can be claimed by other apps, Universal Links cannot** — this is why unverified scheme handlers are the collision/parameter-injection surface and verified links are not. HTTPS must be used to transport data (ATS), and a misconfigured/missing association file silently downgrades the link to Safari. [T1 Apple]
- **App Transport Security** (`NSAppTransportSecurity` in `Info.plist`) is the iOS transport-policy counterpart to Android's network security config; record the app's exception keys where cleartext or relaxed TLS is allowed. [T1 Apple]
- Universal link routing detail: a link tapped inside the app's own `WKWebView` **does** open the app; what does not open the app is a universal link opened via `UIApplication.open(_:options:)`/SwiftUI `openURL`/`NSWorkspace.open` from the app itself. Taps on the **same domain** while browsing that site in Safari stay in Safari (deferred by user intent); a tap on a **different domain** opens the app. No app installed → default browser. (The older note that a universal link handled in an embedded webview goes to Safari is a conflation of these two rules.) [T1 Apple universal links]
- **Custom schemes** are declared in `CFBundleURLTypes`; iOS gives partial sender identity: `UIApplication.OpenURLOptionsKey.sourceApplication` contains the sender's bundle ID **only when it is from the same team** and is `nil` otherwise — it is not an authorization control. That key is deprecated at iOS 26 in favor of `UISceneOpenURLOptions.sourceApplication`; treat sender identity as advisory on both platforms. `UIApplication.canOpenURL(_:)` requires declarations in `LSApplicationQueriesSchemes` (max **50** entries for apps linked on/after iOS 15; **25** on/after iOS 27) and is itself deprecated in favor of attempting the open; `open(_:)` is not quota-limited. [T1 Apple canOpenURL] [T1 Apple sourceApplication]

### iOS storage: Keychain, file protection, and backups

- **Keychain accessibility** (`kSecAttrAccessible`) from most to least restrictive: **WhenPasscodeSet** (item unusable — and deleted if the passcode is removed — requires a passcode, accessible only unlocked), **WhenUnlocked** (the default when unspecified), **AfterFirstUnlock** (usable by background processes until the next restart), **Always** (not recommended). A `ThisDeviceOnly` suffix means the item restores only to the same device and is **not** migrated into a different device's restore. `SecAccessControl` with `kSecAccessControlUserPresence` requires biometry or passcode at use time, and `kSecAccessControlApplicationPassword` adds an app-specific password. [T1 Apple keychain accessibility]
- **File protection** levels (`NSFileProtectionKey` / `FileProtectionType`) decide what a stolen-device or backup oracle can read: `complete` (unreadable/unwritable while locked or booting), `completeUnlessOpen` (encrypted once closed), `completeUntilFirstUserAuthentication` (readable after first boot unlock), `none`. Record the level per sensitive file rather than assuming the app's default. [T1 Apple file protection]
- **Backup exposure**: an iOS device backup contains all subdirectories of the app's private directory **except `Library/Caches/`**; `Documents/` and `Library/Application Support/` are always included unless the app marks them with `NSURLIsExcludedFromBackupKey` (preferable to the old extended-attribute approach). Check `Manifest.plist` (`IsEncrypted`) to know whether a backup is encrypted, and remember that a **tampered backup restored to a non-jailbroken device** is a documented way to strip app-side locks (e.g. deleting a `pin_code` plist key restored a wallet's UI lock). [T1 OWASP MASTG TEST-0058]
- **Shared storage is an IPC surface**: App Groups (`com.apple.security.application-groups`, `group.<name>`) let apps from one team share containers, keychain access groups, and IPC primitives — Mach IPC/XPC service names, POSIX semaphores and shared memory, and UNIX domain sockets must be named `<group identifier>.<unique name>` and the socket path must live in the group container. Registered app groups double as keychain access groups. When a target ships an extension, enumerate the group container and the shared `UserDefaults(suiteName:)` as data channels, not just the main app's sandbox. [T1 Apple app groups]

### iOS pasteboard and Android clipboard

- On **iOS 16+**, a programmatic pasteboard read raises a user approval alert; `UIPasteControl` is the documented prompt-free path because the paste is user-initiated. An app that reads the general pasteboard without the alert is either reading content it placed itself or using a path that bypasses the prompt — that difference is the oracle, and the server-side proof is what the app does with the pasted value. [T1 Apple UIPasteControl]
- On **Android 13+** the system shows a copy preview; apps must set `ClipDescription.EXTRA_IS_SENSITIVE` (or the legacy extra string `android.content.extra.IS_SENSITIVE` when compiled against a lower SDK) to keep sensitive content out of the preview — this must be done regardless of target API level. [T1 Android copy-paste]
- On **Android 12+**, calling `getPrimaryClip()` normally shows a toast (“APP pasted from your clipboard”). It is suppressed for the app's own clip data, for repeat reads of the same app's data, and for metadata reads via `getPrimaryClipDescription()`. This makes clipboard reads observable in a log/screen recording without instrumentation. [T1 Android copy-paste]

### Pinning bypass, root/jailbreak, and attestation signals (supporting only)

- MASTG's Android bypass technique enumerates the practical paths: Frida (`frida-multiple-unpinning` covers more cases than objection's script), `objection`'s `android sslpinning disable`, and Xposed modules (TrustMeAlready, SSLUnpinning). When automated bypass fails, pin the implementation statically: `grep -ri "sha256\|sha1" ./smali`, `find ./assets -type f \( -iname '*.cer' -o -iname '*.crt' \)`, `find ./ -type f \( -iname '*.jks' -o -iname '*.bks' \)`, then replace the hash/file/truststore with the proxy CA. [T1 OWASP MASTG TECH-0012]
- Library-identified pinning is hookable by signature: identify the library from strings/licences (e.g. OkHttp `CertificatePinner.Builder.add`), then hook candidate methods and print arguments until the domain and pin hash appear. Native pinning requires reverse engineering the library instead. [T1 OWASP MASTG TECH-0012]
- iOS bypass: `objection`'s `ios sslpinning disable` works on jailbroken devices with `frida-server`, or by injecting the Frida Gadget into a non-jailbroken IPA; SSL Kill Switch 2 (Cydia) hooks high-level APIs. Static fallbacks: replace a bundled certificate (and the hardcoded SHA if present), binary-patch OpenSSL, or disable pinning in source by searching `NSURLSession`, `CFStream`, `AFNetworking`, and strings like “pinning”, “X.509”, “Certificate”. [T1 OWASP MASTG TECH-0064]
- **Root detection signals to recognize (not to defeat for a finding)**: file existence (`/system/xbin/su`, `/system/app/Superuser.apk`, `/system/etc/init.d/99SuperSUDaemon`, `/dev/com.koushikdutta.superuser.daemon/`, `/system/xbin/busybox`), `su` on `PATH`, privileged-command execution via `Runtime.exec`, running-process names (`supersu`, `superuser`, `daemonsu`), root-manager packages (`com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.noshufou.android.su`, `com.koushikdutta.superuser`), writable system/data mounts, and `Build.TAGS` containing `test-keys` or missing Google OTA certificates. On **Android 11+** package visibility hides non-declared packages, so package-based checks can silently produce false negatives (`NameNotFoundException`) unless `<queries>` or `QUERY_ALL_PACKAGES` is used. [T1 OWASP MASTG KNOW-0027]
- **Jailbreak detection signals**: file/directory lists (`/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/bin/bash`, `/usr/sbin/sshd`, `/usr/sbin/frida-server`, `/usr/bin/cycript`, …), writing outside the sandbox (e.g. `/private/jailbreak.txt`), and `canOpenURL("cydia://")`. [T1 OWASP MASTG KNOW-0084]
- **Attestation is the server-side counterpart to those client checks.** Android: Play Integrity returns `appRecognitionVerdict` (`PLAY_RECOGNIZED`/`UNRECOGNIZED_VERSION`/`UNEVALUATED`), `deviceRecognitionVerdict` (`MEETS_DEVICE_INTEGRITY`; opt-in `MEETS_BASIC_INTEGRITY`, `MEETS_STRONG_INTEGRITY`, `MEETS_VIRTUAL_INTEGRITY`), plus optional `appAccessRiskVerdict` (`appsDetected`: `KNOWN_/UNKNOWN_CAPTURING|CONTROLLING|OVERLAYS`) and `playProtectVerdict`. Apple: App Attest (`DCAppAttestService`) generates a hardware key per user/device, `attestKey` certifies it against a server challenge, and `generateAssertion` signs later requests; keys do not survive reinstall, device migration, or backup restore, and `isSupported` is false on some devices. A verdict that is requested but not enforced server-side is the gap worth reporting. [T1 Android Play Integrity] [T1 Apple App Attest]
- Pinning and root-detection posture is a *resilience* signal, not a server-side finding: tools such as **Frida** and **Objection** (with **SSL Kill Switch**) exist to observe traffic, but the oracle must still be server-side on researcher data. [T2 research]
- A MITM proxy with an injected user CA only intercepts when the app trusts user CAs — on API 24+ user CAs are not trusted by default, so proxy trust usually requires a debug / `debug-overrides` build or a repackaged app (see the network-config table above). [T1 Android]
- Emulator networking and VPN profiles can change headers, TLS settings, and timing; confirm every oracle on the observed real build outside the intercept path before reporting.
- Keep the intercept path out of the *proof*: it is a way to find candidates, not a way to demonstrate server-side impact.

### Feature flags, cohorts, and interception hygiene

- Mobile API versions frequently lag or lead web versions; version-specific authz middleware is the productive differential, not version-string age.
- Feature flags and staged rollouts can cohort researcher accounts differently; fix cohort, build number, and account before concluding a flag-gated gap.
- Push and sync behaviour differs by OS background policy and vendor gateway; subscription and redelivery quirks are per-platform observations.
- Intercepting proxies, VPN profiles, and emulator networking can alter headers, TLS, and timing; validate every oracle outside the intercept path before reporting.
- Map observations to **OWASP MASVS** control areas (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE) and the corresponding **MASWE** weaknesses so the finding lands on a recognized control rather than a raw tool output. [T1 OWASP MASTG]
- Android's own risk taxonomy mirrors this mapping per risk page (each is tagged with an OWASP category, e.g. Intent redirection → MASVS-PLATFORM), which is the vocabulary to reuse in a report. [T1 Android risks]

MASVS area → mobile seam to test:

| MASVS area | Representative seam |
|---|---|
| PLATFORM | deep links, exported components, WebView bridge, intent redirection, IPC |
| NETWORK | cleartext, pinning, trust anchors (config above) |
| STORAGE | backup, keychain/keystore, WebView storage, local caches replayed |
| AUTH | mobile-vs-web session, token scope, refresh, attestation gates |
| CODE / RESILIENCE | update channel, pinning bypass, root/jailbreak checks (supporting only) |

### Client-mining checklist (record each with its source location before sending traffic)

- Hosts and base paths: bundle strings, config files, `Info.plist` / `AndroidManifest.xml`, and observed traffic.
- Routes and versions: path fragments, `/v1/`/`/v2/` markers, and GraphQL operation names.
- Auth material: token storage location, refresh endpoint, and whether a mobile-only token type is issued.
- Link handlers: `CFBundleURLSchemes` (iOS) and `<data android:scheme>` (Android); note which filters use `autoVerify`, and record the `applinks:` / `appclips:` entitlement entries and AASA `components`/`paths` for each declared host.
- WebView surface: bridge interface names, `@JavascriptInterface` methods, `WebMessageListener` object names and origin rules, and the hosts the view may load.
- Intent surface: every component with an intent filter and its effective `exported` value, nested-intent extra keys and their sinks, `PendingIntent` creations (mutability + base-intent explicitness), and provider permissions.
- Flags and gates: A/B keys, staged-rollout values, and force-upgrade thresholds.
- Storage: `allowBackup`/`fullBackupContent`/`dataExtractionRules`/`backupAgent`, keychain accessibility attributes and access groups, keystore key authorizations, and any cached API responses replayed offline.
- Attestation: which integrity verdicts/assertions the client requests and at which endpoints the server appears to consume them.
- For every candidate, mark the representation (mobile-only route, flag-gated path, or shared) before replaying.

## References

- [T1 vendor] Android Developers — Verify App Links (`autoVerify`, `.well-known/assetlinks.json`, all-hosts ≤API 30, Android 15 seven-day re-verify, `adb` commands): https://developer.android.com/training/app-links/verify-android-applinks
- [T1 vendor] Android Developers — Network security configuration (cleartext/CA defaults by API level, `debug-overrides`, `pin-set`/SPKI SHA-256, CT/ECH by API level): https://developer.android.com/privacy-and-security/security-config
- [T1 vendor] Android Developers — Build web apps in WebView (`addJavascriptInterface` danger, `@JavascriptInterface`, `shouldOverrideUrlLoading`, `setSupportMultipleWindows`): https://developer.android.com/develop/ui/views/layout/webapps/webview
- [T1 vendor] Android Developers — `WebSettings` reference (file-access defaults and API 30 deprecations, WebViewAssetLoader recommendation): https://developer.android.com/reference/android/webkit/WebSettings
- [T1 vendor] Android Developers — Intent redirection risk page (nested/parsed intents, `IntentSanitizer`, grant flags, Android 16 `removeLaunchSecurityProtection`, StrictMode): https://developer.android.com/privacy-and-security/risks/intent-redirection
- [T1 vendor] Android Developers — Mitigate security risks index (MASVS-grouped risk pages: content resolvers, implicit intent hijacking, broadcast receivers, pending intents, StrandHogg, tapjacking, `android:exported`): https://developer.android.com/privacy-and-security/risks
- [T1 vendor] Android Developers — Behavior changes Android 12 (`android:exported` requirement, PendingIntent mutability): https://developer.android.com/about/versions/12/behavior-changes-12
- [T1 vendor] Android Developers — Behavior changes Android 14 (implicit intents to exported components only, mutable PendingIntent exception, `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED`): https://developer.android.com/about/versions/14/behavior-changes-14
- [T1 vendor] Android Developers — Behavior changes Android 15 (StrictMode safer intents): https://developer.android.com/about/versions/15/behavior-changes-15
- [T1 vendor] Android Developers — `<activity>` manifest element (`android:exported` default when no intent filters): https://developer.android.com/guide/topics/manifest/activity-element
- [T1 vendor] Android Developers — Auto Backup (`allowBackup`, `data-extraction-rules`, cloud vs D2D, `disableIfNoEncryptionCapabilities`, cross-platform transfer): https://developer.android.com/identity/data/autobackup
- [T1 vendor] Android Developers — Android Keystore system (non-exportable key material, TEE/StrongBox, `getSecurityLevel`, `setUserAuthenticationParameters`): https://developer.android.com/privacy-and-security/keystore
- [T1 vendor] Android Developers — Copy and paste (Android 13 preview, `ClipDescription.EXTRA_IS_SENSITIVE`, Android 12 paste toast): https://developer.android.com/develop/ui/views/touch-and-input/copy-paste
- [T1 vendor] Google — Play Integrity verdicts (`appRecognitionVerdict`, `deviceRecognitionVerdict` labels, app access risk, Play Protect): https://developer.android.com/google/play/integrity/verdicts
- [T1 vendor] OWASP MASTG — Deep Links (custom scheme vs App Links, deep-link collision, verification, caller identity): https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/
- [T1 vendor] OWASP MASTG — WebViews (bridge mechanisms, file/content access, storage, WebViewClient trust): https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/
- [T1 vendor] OWASP MASTG — Securely Load File Content in a WebView (WebViewAssetLoader; explicit false settings; MASTG-TEST-0250–0253, 0334): https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/
- [T1 vendor] OWASP MASTG — MASTG-TEST-0030 PendingIntent (implicit base intent + mutability; CVE-2020-0389): https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/
- [T1 vendor] OWASP MASTG — MASTG-TEST-0026 Implicit intents and unvalidated result URIs: https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/
- [T1 vendor] OWASP MASTG — MASTG-TECH-0012 Bypassing Certificate Pinning (Android): https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/
- [T1 vendor] OWASP MASTG — MASTG-TECH-0064 Bypassing Certificate Pinning (iOS): https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/
- [T1 vendor] OWASP MASTG — MASTG-KNOW-0027 Root Detection (file/process/package/build signals; Android 11 package visibility): https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027/
- [T1 vendor] OWASP MASTG — MASTG-KNOW-0084 Jailbreak Detection (file lists, sandbox write check, `cydia://`): https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/
- [T1 vendor] OWASP MASTG — MASTG-TECH-0128 Backup and restore with `bmgr`; `adb backup` restricted since Android 12: https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0128/
- [T1 vendor] OWASP MASTG — MASTG-TEST-0262 backup configuration exclusion (`dataExtractionRules`, `cloud-backup`, `device-transfer`): https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/
- [T1 vendor] OWASP MASTG — MASTG-TEST-0058 iOS backups (`Library/Caches` exclusion, `NSURLIsExcludedFromBackupKey`, `Manifest.plist` `IsEncrypted`, tampered-backup restore): https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0058/
- [T1 vendor] OWASP MASTG / MASVS / MASWE (controls → weaknesses mapping): https://mas.owasp.org/MASTG/ ; https://mas.owasp.org/MASVS/ ; https://mas.owasp.org/MASWE/
- [T1 vendor] Apple — Supporting associated domains (`components` matching, per-subdomain files and entitlement entries, Apple CDN and weekly refresh, `?mode=` alternate mode): https://developer.apple.com/documentation/xcode/supporting-associated-domains
- [T1 vendor] Apple — Allowing apps and websites to link to your content (WKWebView link taps open the app; `UIApplication.open` does not; same-domain Safari behavior): https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content
- [T1 vendor] Apple — Universal Links / association file archive reference (`apple-app-site-association`, `paths`, 128 KB, `applinks` entitlement): https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html
- [T1 vendor] Apple — `canOpenURL(_:)` (`LSApplicationQueriesSchemes` limits: 50 at iOS 15, 25 at iOS 27; deprecation): https://developer.apple.com/documentation/uikit/uiapplication/canopenurl(_:)
- [T1 vendor] Apple — `sourceApplication` (same-team only, `nil` cross-team; deprecated at iOS 26): https://developer.apple.com/documentation/uikit/uiapplication/openurloptionskey/sourceapplication
- [T1 vendor] Apple — Restricting keychain item accessibility (WhenPasscodeSet / WhenUnlocked / AfterFirstUnlock / Always, `ThisDeviceOnly`, `SecAccessControl` user presence): https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility
- [T1 vendor] Apple — `FileProtectionType` (`complete`, `completeUnlessOpen`, `completeUntilFirstUserAuthentication`, `none`): https://developer.apple.com/documentation/foundation/fileprotectiontype
- [T1 vendor] Apple — App Groups entitlement (shared containers, keychain access groups, Mach IPC/XPC/semaphores/shared memory/UNIX sockets naming): https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups
- [T1 vendor] Apple — Establishing your app's integrity (App Attest key generation, attestation challenge, assertions, `isSupported`, keys not surviving reinstall/migration/restore): https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
- [T1 vendor] Apple — `UIPasteControl` (iOS 16+ programmatic paste raises a user approval alert; this control pastes without a prompt): https://developer.apple.com/documentation/uikit/uipastecontrol
- [T1 vendor] Apple — NSAppTransportSecurity (ATS transport policy / cleartext exceptions): https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity
- [T1 vendor] Platform documentation for the observed OS version (deep links, universal links, webview, storage, push)
- [T1 vendor] OWASP MASVS/MSTG: deep-link testing (MASWE): https://mas.owasp.org ; platform-interaction tests: https://github.com/OWASP/owasp-mstg
- [T2 research] OWASP Mobile Top 10 testing 2026 (pinning bypass via Frida): https://www.decryptiondigest.com
- [T2 research] Mobile pen-testing guide 2026 (pinning, Objection, SSL Kill Switch): https://securitywall.co
- [T2 research] OWASP MASVS and MASTG guide 2026: https://appsecsanta.com
- [T1 vendor] API authorization guidance for versioned, hidden, and flagged server routes reached by clients
- web-browser/browser.md for webview, navigation, and origin-trust detail reused from the browser surface
- Framework and backend documentation for the fingerprinted API stack behind the mobile client
