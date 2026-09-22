#!/usr/bin/env python3
"""Cross-language scope parity: Python `scope_check` vs the enforcer `scopeReasonFor`.

For every (engagement.yaml variant, probe URL) pair the two implementations must agree
on the decision: `scope_check(...)["in_scope"]` is True exactly when the JS
`scopeReasonFor` returns undefined (allow); any returned reason string is a deny.
Run: python3 tools/test_scope_parity.py (exits non-zero on mismatch; SKIPs when node is
unavailable).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
ENFORCER = REPO / "dsh-plugin" / "index.js"
sys.path.insert(0, str(TOOLS))
from control_plane import scope_check  # noqa: E402

# JSON.stringify(undefined) has no string form and writing it throws in Node, so the
# script stringifies first; `undefined` on stdout means "allow" (no reason).
RUNNER = (
    "import {scopeReasonFor} from " + json.dumps(ENFORCER.as_uri()) + ";"
    "process.stdout.write(String(JSON.stringify(scopeReasonFor(process.argv[1], process.argv[2]))))"
)

VARIANTS: list[tuple[str, str | None]] = [
    ("no-engagement-file", None),
    ("scope-block-absent", 'program:\n  name: "x"\n'),
    ("canonical-block-list", 'scope:\n  assets:\n  - "t.example"\n  - "*.wild.example"\n'),
    ("inline-empty-assets", "scope:\n  assets: []\n"),
    ("empty-assets-entry", "scope:\n  assets:\n"),
    ("legacy-top-level-assets", "assets:\n  - t.example\n"),
    ("legacy-and-scope-before",
     "assets:\n  - legacy.example\n\nscope:\n  assets:\n  - t.example\n"),
    ("legacy-and-scope-after",
     "scope:\n  assets:\n  - t.example\n\nassets:\n  - legacy.example\n"),
    ("nested-assets-under-child-key",
     "scope:\n  exclusions:\n    assets:\n    - nested.example\n  assets:\n  - t.example\n"),
    ("nested-assets-only", "program:\n  assets:\n  - nested.example\n"),
    ("duplicate-assets-inside-scope",
     "scope:\n  assets:\n  - t.example\n  assets:\n  - evil.example\n"),
    ("col0-comment-and-block-list",
     "# program assets\nassets:\n  - t.example\n"),
    ("cr-only-endings", 'scope:\r  assets:\r  - "t.example"\r'),
    ("crlf-endings", 'scope:\r\n  assets:\r\n  - "t.example"\r\n'),
    ("gate-none", "scope:\n  gate: none\n"),
    ("gate-none-trailing-comment", "scope:\n  gate: none  # opt-out\n"),
    ("commented-out-gate", "scope:\n  # gate: none\n"),
    ("gate-nonexistent", "scope:\n  gate: nonexistent\n"),
    ("nested-gate-under-child-key", "scope:\n  exclusions:\n    gate: none\n"),
    ("unparseable-nested-item", "scope:\n  assets:\n    - {host: nested}\n"),
]

PROBES: list[str] = [
    "https://t.example/a",
    "https://a.wild.example/x",
    "https://wild.example/",
    "https://evil.example/x",
    "https://user:pass@t.example/a",
    "https://user@t.example/a",
    "https://t.example./a",
    "HTTPS://T.EXAMPLE/a",
    "http://127.0.0.1:9\\@t.example/",
    "http://t.example%5cevil/",
    "http://t.example%5Cevil/",
    "http://t.example\\evil/",
    "t.example/a",
]


def node_decision(root: Path, url: str) -> bool:
    """True when the enforcer allows the URL (undefined reason), False when it denies."""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", RUNNER, str(root), url],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"node exit {proc.returncode}")
    raw = proc.stdout.strip()
    if raw == "undefined":
        return True
    if raw.startswith('"'):
        return False
    raise RuntimeError(f"unexpected node output: {raw!r}")


def main() -> int:
    if shutil.which("node") is None:
        print("SKIP (node unavailable) — parity NOT verified")
        return 0
    passed = 0
    failures: list[str] = []
    base = Path(tempfile.mkdtemp(prefix="scope-parity-"))
    try:
        for index, (label, yaml_text) in enumerate(VARIANTS):
            root = base / f"v{index:02d}-{label}"
            (root / "00_control").mkdir(parents=True)
            (root / "OS_VERSION").write_text("7.1\n")
            if yaml_text is not None:
                (root / "00_control" / "engagement.yaml").write_text(yaml_text)
            for url in PROBES:
                name = f"{label} :: {url}"
                try:
                    js_allow = node_decision(root, url)
                except RuntimeError as exc:
                    failures.append(name)
                    print(f"ERROR: {name}: {exc}")
                    continue
                py_allow = bool(scope_check(root, url)["in_scope"])
                if py_allow == js_allow:
                    passed += 1
                    print(f"ok: {name}")
                else:
                    failures.append(name)
                    print(f"FAIL: {name}: python={'allow' if py_allow else 'deny'} "
                          f"node={'allow' if js_allow else 'deny'}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{passed}/{passed + len(failures)} parity checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
