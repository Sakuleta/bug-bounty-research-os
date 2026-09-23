#!/usr/bin/env python3
"""Replay-diff harness for the controlled executor.

LAB MODE (no argument): start a stdlib HTTP server on 127.0.0.1 with canned endpoints,
build a temporary engagement workspace whose scope is exactly that localhost origin, and
execute a fixture set of canonical request shapes through the JS executor core
(`dsh-plugin/index.js` `runControlledRequest`) TWICE with fresh preflight tokens. For
every shape the two runs must replay identically: HTTP status, the response header set
after redaction, and the body sha256 read back from the captures. The `?token=` fixture
also proves the capture masks the credential.

INTEGRITY MODE (`python3 tools/test_replay.py <workspace>`): the path must be a research
workspace (`OS_VERSION` plus `08_artifacts/raw` or `11_runtime/events.jsonl`); for every
`08_artifacts/raw/*.http` capture it parses the request and status lines, re-scans the
bytes for secret-shaped values, and asserts the canonical masker is idempotent on the
file (applying it again changes nothing). Every failure fragment it prints is routed
through `control_plane.redact`; a secret hit prints only the pattern name, the file and
the line number, never the raw line or bytes.

Lab mode needs `node`; without it the harness prints a SKIP line and exits 0 (nothing was
verified — read that line). Integrity mode is pure Python and does not need node.

No external network; deterministic; temp workspaces are removed. Run:
  python3 tools/test_replay.py [WORKSPACE]
"""
from __future__ import annotations

import difflib
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
ENFORCER = REPO / "dsh-plugin" / "index.js"
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane, redact, secret_pattern_hits  # noqa: E402

TOOL_FILES = ("control_plane.py", "researchctl.py", "knowledge_index.py",
              "build_context.py", "ts_triage.py", "ts_claims.py", "ts_http.py",
              "ts_cost.py")

NODE_RUNNER = (
    "import {runControlledRequest} from " + json.dumps(ENFORCER.as_uri()) + ";"
    "const [root, argsJson] = process.argv.slice(1);"
    "const result = await runControlledRequest({root, args: JSON.parse(argsJson)});"
    "process.stdout.write(JSON.stringify(result))"
)


class CannedHandler(BaseHTTPRequestHandler):
    """Deterministic lab endpoints. No Server/Date headers: the capture must be stable."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence the default stderr access log
        pass

    def send_response(self, code, message=None):  # drop the implicit Server/Date headers
        self.send_response_only(code, message)

    def _respond(self, code: int, body: bytes, extra_headers: list[tuple[str, str]] | None = None):
        self.send_response(code)  # the override above drops the implicit Server/Date headers
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ok":
            self._respond(200, b'{"ok":true,"endpoint":"/ok"}', [("X-Lab-Endpoint", "ok")])
        elif path == "/secret":
            self._respond(200, b'{"ok":true,"endpoint":"/secret"}')
        elif path == "/redirect":
            self._respond(302, b"", [("Location", f"http://127.0.0.1:{self.server.server_port}/ok")])
        else:
            self._respond(404, b'{"error":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.split("?", 1)[0] == "/echo":
            self._respond(200, body)
        else:
            self._respond(404, b'{"error":"not found"}')


def start_server() -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), CannedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_port


def build_workspace(base: Path, port: int) -> Path:
    """Temporary engagement workspace: copied tools, localhost scope, RUNNING cycle."""
    root = base / "workspace"
    (root / "00_control").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    for name in TOOL_FILES:
        shutil.copy2(TOOLS / name, root / "tools" / name)
    shutil.copy2(REPO / "OS_VERSION", root / "OS_VERSION")
    (root / "00_control" / "engagement.yaml").write_text(
        "# Replay fixture — localhost lab only.\n"
        'external_judgment: "DENIED"\n'
        "scope:\n"
        "  assets:\n"
        f'  - "127.0.0.1:{port}"\n')
    for d in ("02_surface", "03_hypotheses/active", "03_hypotheses/archive",
              "04_cycles", "08_artifacts/raw", "10_learning", "11_runtime",
              "12_knowledge/fixture"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "02_surface" / "endpoints.yaml").write_text("endpoints: []\n")
    (root / "12_knowledge" / "fixture" / "fixture.md").write_text("# Replay fixture pack\n")
    (root / "12_knowledge" / "INDEX.yaml").write_text(
        "packs:\n"
        "  fixture:\n    load_when: [replay, determinism, fixture]\n    files: [fixture.md]\n")
    (root / "10_learning" / "freshness.yaml").write_text("components: []\n")
    (root / "10_learning" / "unknowns.yaml").write_text("unknowns: []\n")
    (root / "10_learning" / "assumptions.yaml").write_text("assumptions: []\n")
    (root / "11_runtime" / "events.jsonl").write_text("")
    (root / "11_runtime" / "tool-registry.yaml").write_text("tools: []\n")
    (root / "11_runtime" / "lab-status.yaml").write_text("status: UNKNOWN\n")
    cp = ControlPlane(root)
    cp.create_cycle("C-0001", {
        "id": "C-0001", "type": "DISCOVERY", "objective": "replay determinism fixture",
        "allowed_scope": [f"127.0.0.1:{port}"], "stop_conditions": ["fixture ends"],
        "controls": [], "status": "PLANNED",
        "knowledge_triage": [{"pack": "fixture", "verdict": "SKIP",
                              "reason": "replay determinism fixture covers this pack"}],
    })
    cycle_dir = root / "04_cycles" / "C-0001"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    (cycle_dir / "objective.md").write_text(
        "# Cycle Objective\n\n## Question\nDoes the fixture replay byte-identically?\n\n"
        "## Minimal test\nTwo executor runs over the same canned endpoints.\n")
    cp.transition_cycle("C-0001", "READY", reason="fixture ready")
    cp.transition_cycle("C-0001", "RUNNING", reason="fixture running")
    return root


def fixture_shapes(port: int) -> list[dict]:
    """Canonical shapes covering headers, a body, a secret query and a redirect."""
    base = f"http://127.0.0.1:{port}"
    return [
        {"label": "GET /ok", "args": {"method": "GET", "url": f"{base}/ok", "principal": "researcher-A",
                                      "headers": {"Accept": "application/json"}}},
        {"label": "POST /echo (body)", "args": {"method": "POST", "url": f"{base}/echo",
                                                "principal": "researcher-A",
                                                "headers": {"Content-Type": "application/json"},
                                                "body": '{"probe":"replay-1"}'}},
        {"label": "GET /secret?token=abc", "args": {"method": "GET", "url": f"{base}/secret?token=abc",
                                                    "principal": "researcher-A"}},
        {"label": "GET /redirect", "args": {"method": "GET", "url": f"{base}/redirect",
                                            "principal": "researcher-A"}},
        {"label": "lowercase get /ok", "args": {"method": "get", "url": f"{base}/ok",
                                                "principal": "researcher-A"}},
    ]


def prepare_token(root: Path, args: dict, label: str) -> dict:
    cp = ControlPlane(root)
    shape = {"method": args["method"], "url": args["url"], "principal": args["principal"]}
    if args.get("headers"):
        shape["headers"] = args["headers"]
    if args.get("body"):
        shape["body"] = args["body"]
    return cp.prepare_action({
        "cycle_id": "C-0001",
        "target": f"local replay fixture ({label})",
        "scope_status": "IN_SCOPE",
        "account": "researcher-A",
        "object_owner": "researcher-A",
        "purpose": "replay determinism check",
        "hypothesis": "replay fixture (no hypothesis)",
        "expected_secure": "n/a",
        "expected_vulnerable": "n/a",
        "side_effect": "none",
        "stop_condition": "stop after the fixture call",
        "tool_family": "http",
        "request_shape": shape,
    })


def execute(root: Path, args: dict) -> dict:
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", NODE_RUNNER, str(root), json.dumps(args)],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"node exit {proc.returncode}")
    return json.loads(proc.stdout)


def secret_line_numbers(text: str) -> list[int]:
    """1-based lines carrying a secret-shaped value; the line text itself is never printed."""
    return [i for i, line in enumerate(text.splitlines(), 1) if secret_pattern_hits(line)]


def mask(text: str) -> str:
    """Every failure fragment goes through the canonical masker before printing."""
    return redact(text)


def workspace_problem(path: Path) -> str | None:
    """Why `path` is not a research workspace, or None. Integrity mode refuses anything
    else: a random directory has no captures and would otherwise pass vacuously."""
    if not path.is_dir():
        return f"{path} is not a directory"
    if not (path / "OS_VERSION").is_file():
        return f"{path} has no OS_VERSION"
    if not ((path / "08_artifacts" / "raw").is_dir() or (path / "11_runtime" / "events.jsonl").is_file()):
        return f"{path} has neither 08_artifacts/raw nor 11_runtime/events.jsonl"
    return None


def parse_capture(text: str) -> dict:
    """Request line, response status line, post-redaction header set and body bytes."""
    req_marker = "--- request\n"
    resp_marker = "--- response\n"
    if req_marker not in text or resp_marker not in text:
        return {"request_line": "", "status": "", "headers": [], "body": ""}
    request_block = text.split(req_marker, 1)[1].split(resp_marker, 1)[0]
    response_block = text.split(resp_marker, 1)[1]
    request_line = request_block.split("\n", 1)[0].strip()
    lines = response_block.split("\n")
    status_line = lines[0].strip()
    headers: list[str] = []
    index = 1
    while index < len(lines) and lines[index] != "":
        headers.append(lines[index])
        index += 1
    body = "\n".join(lines[index + 1:]).rstrip("\n")
    return {"request_line": request_line, "status": status_line, "headers": headers, "body": body}


def capture_for(root: Path, action_id: str) -> Path | None:
    matches = sorted((root / "08_artifacts" / "raw").glob(f"{action_id}-*.http"))
    return matches[-1] if matches else None


def run_fixture(root: Path, shapes: list[dict]) -> dict[str, dict]:
    """One pass over the fixture set: fresh token, executor call, parsed capture."""
    out: dict[str, dict] = {}
    for shape in shapes:
        token = prepare_token(root, shape["args"], shape["label"])
        result = execute(root, shape["args"])
        if not result.get("ok"):
            raise RuntimeError(f"{shape['label']}: executor refused: {result.get('text', '')}")
        capture = capture_for(root, token["action_id"])
        if capture is None:
            raise RuntimeError(f"{shape['label']}: no capture for {token['action_id']}")
        out[shape["label"]] = {**parse_capture(capture.read_text(errors="ignore")),
                               "capture": capture.name}
    return out


def lab_mode() -> int:
    if shutil.which("node") is None:
        print("SKIP (node unavailable) — replay diff NOT verified")
        return 0
    server, thread, port = start_server()
    base = Path(tempfile.mkdtemp(prefix="replay-lab-"))
    failures: list[str] = []
    passed = 0
    try:
        root = build_workspace(base, port)
        shapes = fixture_shapes(port)
        run_a = run_fixture(root, shapes)
        run_b = run_fixture(root, shapes)
        for shape in shapes:
            label = shape["label"]
            fact_a = (run_a[label]["status"], run_a[label]["headers"], hashlib.sha256(
                run_a[label]["body"].encode("utf-8")).hexdigest())
            fact_b = (run_b[label]["status"], run_b[label]["headers"], hashlib.sha256(
                run_b[label]["body"].encode("utf-8")).hexdigest())
            if fact_a == fact_b:
                passed += 1
                print(f"ok: replay identical — {label} ({fact_a[0]})")
            else:
                failures.append(label)
                print(f"FAIL: replay drift — {label}")
                for line in difflib.unified_diff(
                        json.dumps(fact_a, indent=2).splitlines(),
                        json.dumps(fact_b, indent=2).splitlines(),
                        fromfile=f"A {run_a[label]['capture']}",
                        tofile=f"B {run_b[label]['capture']}", lineterm=""):
                    print(mask(line))
        secret_line = run_a["GET /secret?token=abc"]["request_line"]
        if "token=[REDACTED]" in secret_line and "abc" not in secret_line:
            passed += 1
            print(f"ok: capture masks the secret query value ({mask(secret_line.split(' ', 1)[1])})")
        else:
            failures.append("secret masking")
            print(f"FAIL: secret query value not masked in capture: {mask(secret_line)!r}")
    except Exception as exc:  # a harness error is a failure, never a silent pass
        failures.append(str(exc))
        print(f"FAIL: replay harness error: {mask(str(exc))}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{passed}/{passed + len(failures)} replay checks passed")
    return 1 if failures else 0


def integrity_mode(workspace: Path) -> int:
    problem = workspace_problem(workspace)
    if problem:
        print(f"FAIL: {problem} — not a research workspace "
              "(require OS_VERSION plus 08_artifacts/raw or 11_runtime/events.jsonl)")
        return 1
    raw = workspace / "08_artifacts" / "raw"
    captures = sorted(raw.glob("*.http")) if raw.is_dir() else []
    if not captures:
        print(f"no captures under {raw}")
        print("PASS")
        return 0
    failures: list[str] = []
    passed = 0
    for path in captures:
        text = path.read_text(errors="ignore")
        parsed = parse_capture(text)
        if not parsed["request_line"] or not parsed["status"]:
            failures.append(f"{path.name}: missing request or status line")
            print(f"FAIL: {path.name}: missing request or status line")
            continue
        hits = secret_pattern_hits(text)
        if hits:
            lines = secret_line_numbers(text)
            failures.append(f"{path.name}: secret-shaped value")
            print(f"FAIL: {path.name}: secret-shaped value ({hits[0]}) at line "
                  f"{', '.join(map(str, lines)) or '?'} — raw line withheld")
            continue
        if redact(text) != text:
            failures.append(f"{path.name}: masker not idempotent")
            print(f"FAIL: {path.name}: canonical masker is not idempotent on the capture bytes")
            for line in difflib.unified_diff(text.splitlines(), redact(text).splitlines(),
                                             fromfile="capture", tofile="re-masked", lineterm=""):
                print(mask(line))
            continue
        passed += 1
        print(f"ok: {path.name} — {mask(parsed['request_line'])} → {parsed['status']} (masked, idempotent)")
    print(f"\n{passed}/{passed + len(failures)} captures clean")
    return 1 if failures else 0


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: test_replay.py [WORKSPACE]", file=sys.stderr)
        return 2
    if len(sys.argv) == 2:
        return integrity_mode(Path(sys.argv[1]).resolve())
    return lab_mode()


if __name__ == "__main__":
    raise SystemExit(main())
