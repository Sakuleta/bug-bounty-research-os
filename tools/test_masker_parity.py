#!/usr/bin/env python3
"""Masker parity: one secret-pattern source of truth across all three maskers.

tools/secret-patterns.json is the contract. tools/control_plane.py (ledger +
audit), dsh-plugin/index.js (executor captures) and tools/bua/run.mjs (runner
summaries) render it between their GENERATED markers — python3
tools/generate_secret_patterns.py rewrites them. This suite asserts the rendered
blocks match the contract byte-for-byte AND that the three maskers redact the
same fixture shapes (the exec-probe scenario-D shapes: BEGIN-only keys, short
JWTs, github_pat_, xoxb-), so a shape one side misses cannot land raw elsewhere.

Run: python3 tools/test_masker_parity.py (exits non-zero on failure).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from control_plane import _SECRET_PATTERNS, redact  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


contract = json.loads((TOOLS / "secret-patterns.json").read_text(encoding="utf-8"))
sources = [entry["source"] for entry in contract["patterns"]]
check("contract holds eight shapes", len(sources) == 8)

check("python renders the contract in order",
      [p.pattern for p in _SECRET_PATTERNS] == sources)


def js_sources(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    start = text.find("BEGIN-GENERATED-SECRET-PATTERNS")
    end = text.find("END-GENERATED-SECRET-PATTERNS")
    assert start >= 0 and end > start, f"markers missing in {path}"
    out = []
    for line in text[start:end].splitlines():
        line = line.strip()
        if line.startswith("/") and line.endswith("/g,"):
            out.append(line[1:-3])
    return out


check("dsh-plugin renders the contract in order",
      js_sources(REPO / "dsh-plugin" / "index.js") == sources)
check("the bua runner renders the contract in order",
      js_sources(REPO / "tools" / "bua" / "run.mjs") == sources)

gen = subprocess.run([sys.executable, str(TOOLS / "generate_secret_patterns.py"), "--check"],
                     capture_output=True, text=True)
check("generate_secret_patterns --check is clean",
      gen.returncode == 0 and "in sync" in gen.stdout)

# Semantic parity: every fixture is redacted (or not) by all three maskers alike.
FIXTURES = [
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK fake body without end", True),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", True),
    ("short jwt eyJhbGciOi.eyJzdWIiOi.eyJhY2Nlc3Mx tail", True),
    ("full jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl", True),
    ("pat github_pat_ABCDEFGHIJKLMNOPQRSTUVWX", True),
    ("tok ghp_ABCDEFGHIJKLMNOP end", True),
    ("tok xoxb-123456789012-abcdefgh end", True),
    ("tok glpat-ABCDEFGHIJKLMNOPQRST end", True),
    ("key AKIAIOSFODNN7EXAMPLE end", True),
    ("plain hello world, page 2", False),
    ("eyJ too short: eyJh.eyJz. stays", False),
]

node_probe = subprocess.run(
    ["node", "--input-type=module", "-e",
     "import { redactSecrets } from './dsh-plugin/index.js';\n"
     "import { maskText } from './tools/bua/run.mjs';\n"
     "const shapes = " + json.dumps([text for text, _ in FIXTURES]) + ";\n"
     "for (const s of shapes) console.log(JSON.stringify(["
     "redactSecrets(s).includes('[REDACTED]'), maskText(s).includes('[REDACTED]')]));"],
    capture_output=True, text=True, cwd=str(REPO))
assert node_probe.returncode == 0, f"node probe failed: {node_probe.stderr}"
js_rows = [json.loads(line) for line in node_probe.stdout.splitlines() if line.strip()]
assert len(js_rows) == len(FIXTURES), "node probe row count"
for (text, expected), (dsh_hit, bua_hit) in zip(FIXTURES, js_rows):
    py_hit = "[REDACTED]" in redact(text)
    check(f"parity {'redacts' if expected else 'ignores'}: {text[:44]!r}",
          py_hit == expected and dsh_hit == expected and bua_hit == expected)

print(f"\n{len(passed)} checks passed")
