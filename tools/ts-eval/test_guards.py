#!/usr/bin/env python3
"""Guard tests for the one-off TypeSafe evaluation scripts.

The scripts are historical experiment runners, not a test harness: these vectors pin
the live-run guards (no --force / policy DENIED / missing key refuse before any network
call) and the output rule (never overwrite the committed artifacts without --force,
atomic replace with it). Stdlib only; no network is ever reached.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def run(script: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    clean = {k: v for k, v in os.environ.items() if k != "TYPESAFE_API_KEY"}
    if env:
        clean.update(env)
    return subprocess.run([sys.executable, str(HERE / script), *args],
                          capture_output=True, text=True, env=clean, timeout=120)


def policy_root(value: str) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "00_control").mkdir(parents=True)
    (root / "00_control/engagement.yaml").write_text(f'external_judgment: "{value}"\n')
    return root


DENIED_ROOT = policy_root("DENIED")
ALLOWED_ROOT = policy_root("ALLOWED")

# rerank_eval.py: no --force -> refuse; --force + DENIED -> refuse; --force + ALLOWED
# but no key -> refuse. Each case must exit non-zero before any network call.
r = run("rerank_eval.py")
check("rerank refuses to run live without --force",
      r.returncode != 0 and "--force" in r.stdout + r.stderr)
r = run("rerank_eval.py", "--force", "--root", str(DENIED_ROOT))
check("rerank refuses when the engagement policy denies external judgment",
      r.returncode != 0 and "denied" in (r.stdout + r.stderr).lower())
r = run("rerank_eval.py", "--force", "--root", str(ALLOWED_ROOT))
check("rerank refuses without TYPESAFE_API_KEY even when allowed",
      r.returncode != 0 and "TYPESAFE_API_KEY" in r.stdout + r.stderr)

# claims_eval.py: same guard chain.
r = run("claims_eval.py")
check("claims refuses to run live without --force",
      r.returncode != 0 and "--force" in r.stdout + r.stderr)
r = run("claims_eval.py", "--force", "--root", str(DENIED_ROOT))
check("claims refuses when the engagement policy denies external judgment",
      r.returncode != 0 and "denied" in (r.stdout + r.stderr).lower())
r = run("claims_eval.py", "--force", "--root", str(ALLOWED_ROOT))
check("claims refuses without TYPESAFE_API_KEY even when allowed",
      r.returncode != 0 and "TYPESAFE_API_KEY" in r.stdout + r.stderr)

# screen_eval.py / grounding_eval.py / novelty_eval.py / rank_eval.py / label_eval.py /
# honesty_eval.py: same guard chain — no --force -> refuse; --force + DENIED -> refuse;
# --force + ALLOWED but no key -> refuse. Each must exit non-zero before any network call.
for script in ("screen_eval.py", "grounding_eval.py", "novelty_eval.py", "rank_eval.py",
               "label_eval.py", "honesty_eval.py"):
    r = run(script)
    check(f"{script} refuses to run live without --force",
          r.returncode != 0 and "--force" in r.stdout + r.stderr)
    r = run(script, "--force", "--root", str(DENIED_ROOT))
    check(f"{script} refuses when the engagement policy denies external judgment",
          r.returncode != 0 and "denied" in (r.stdout + r.stderr).lower())
    r = run(script, "--force", "--root", str(ALLOWED_ROOT))
    check(f"{script} refuses without TYPESAFE_API_KEY even when allowed",
          r.returncode != 0 and "TYPESAFE_API_KEY" in r.stdout + r.stderr)

# No-go pin: the sprint spec says "Laya stays out" / "Laya in any form" is out of scope
# (SPRINT-v8.3-SPEC.md). The sprint's eval artifacts must not carry a Laya case, source
# URL or description — a scope regression is caught here, offline. The results file may
# keep one provenance note under `removed_for_no_go` naming what was deleted; its `rows`
# must be clean.
for artifact in ("grounding_eval_set.json", "README.md"):
    text = (HERE / artifact).read_text(errors="ignore")
    hits = [i for i, line in enumerate(text.splitlines(), 1) if "laya" in line.lower()]
    check(f"no-go: {artifact} mentions no Laya case/source/description", hits == [])
results_rows = json.dumps(json.loads((HERE / "grounding_results.json").read_text())["rows"])
check("no-go: grounding_results.json rows carry no Laya case/source/description",
      "laya" not in results_rows.lower())
results_meta = json.loads((HERE / "grounding_results.json").read_text())
check("no-go: the removed cases stay recorded as provenance, not as results",
      sorted(results_meta.get("removed_for_no_go", {}).get("cases", [])) == ["laya-apache",
                                                                            "laya-base-near-chance"])

# Output rule: committed artifacts are never overwritten without --force; with --force
# the write is a replace of a temp file (the target is replaced, never half-written).
sys.path.insert(0, str(HERE))
import rerank_eval  # noqa: E402
import claims_eval  # noqa: E402

for module in (rerank_eval, claims_eval):
    target = Path(tempfile.mkdtemp()) / "results.json"
    target.write_text("committed artifact\n")
    wrote = module.write_results(target, [{"kept": False}], force=False)
    check(f"{module.__name__}.write_results leaves committed output alone without --force",
          wrote is False and target.read_text() == "committed artifact\n")
    wrote = module.write_results(target, [{"kept": True}], force=True)
    check(f"{module.__name__}.write_results replaces the target with --force",
          wrote is True and json.loads(target.read_text()) == [{"kept": True}]
          and target.read_text().endswith("\n"))
    leftovers = [p for p in target.parent.iterdir() if p != target]
    check(f"{module.__name__}.write_results leaves no temp files behind", leftovers == [])

print(f"\n{len(passed)}/{len(passed)} passed")
