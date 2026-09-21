#!/usr/bin/env python3
"""Presence check for the installed research-os-enforcer DSH plugin.

For every `<dsh-home>/profiles/*/plugins/research-os-enforcer/index.js` compare the
sha256 with the repo's `dsh-plugin/index.js` and report OK / MISSING / DRIFT. Also read
`<dsh-home>/research-os-enforcer.log` and report the last `APPLY` line's age, warning
when it predates the newest INSTALLED copy that reported OK (the host was not restarted
after the last install; the repo file's mtime says nothing about what the host loaded).
Exit 0 when at least one profile is OK and none are DRIFT, else 1.

Usage: harness_check.py [--repo PATH] [--dsh-home PATH] [--json]
Stdlib only; touches nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

PLUGIN_REL = Path("dsh-plugin") / "index.js"
PROFILE_PLUGIN_REL = Path("plugins") / "research-os-enforcer" / "index.js"
APPLY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+APPLY\b")


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        digest.update(path.read_bytes())
        return digest.hexdigest()
    except OSError:
        return None


def last_apply_time(log_path: Path) -> str | None:
    """Timestamp of the last `APPLY` line in the enforcer log, or None."""
    try:
        text = log_path.read_text(errors="ignore")
    except OSError:
        return None
    last: str | None = None
    for line in text.splitlines():
        match = APPLY_RE.match(line)
        if match:
            last = match.group(1)
    return last


def iso_epoch(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def collect(repo: Path, dsh_home: Path) -> dict:
    plugin = repo / PLUGIN_REL
    want = sha256_file(plugin)
    try:
        plugin_mtime = plugin.stat().st_mtime
    except OSError:
        plugin_mtime = None
    profiles = []
    for profile_dir in sorted((dsh_home / "profiles").glob("*")):
        installed = profile_dir / PROFILE_PLUGIN_REL
        got = sha256_file(installed)
        try:
            installed_mtime = installed.stat().st_mtime
        except OSError:
            installed_mtime = None
        if got is None:
            status = "MISSING"
        elif want is not None and got == want:
            status = "OK"
        else:
            status = "DRIFT"
        profiles.append({"profile": profile_dir.name, "path": str(installed),
                         "status": status, "sha256": got, "mtime": installed_mtime})
    worst = "none" if not profiles else (
        "DRIFT" if any(p["status"] == "DRIFT" for p in profiles)
        else ("OK" if any(p["status"] == "OK" for p in profiles) else "MISSING"))
    ok = any(p["status"] == "OK" for p in profiles) and worst != "DRIFT"

    # The load-bearing comparison: what the host actually loaded is the INSTALLED copy,
    # so the newest OK install's mtime is the one an APPLY must postdate. The repo
    # file's mtime is irrelevant to the running host.
    installed_mtimes = [p["mtime"] for p in profiles
                        if p["status"] == "OK" and p["mtime"] is not None]
    installed_mtime = max(installed_mtimes) if installed_mtimes else None
    apply_at = last_apply_time(dsh_home / "research-os-enforcer.log")
    restart: dict = {"last_apply": apply_at, "age_seconds": None, "message": None,
                     "warning": False, "installed_mtime": installed_mtime}
    if apply_at is None:
        restart["message"] = "no APPLY line in research-os-enforcer.log yet"
    else:
        epoch = iso_epoch(apply_at)
        if epoch is not None:
            restart["age_seconds"] = int(max(0.0, time.time() - epoch))
        if installed_mtime is not None and epoch is not None and epoch < installed_mtime:
            restart["warning"] = True
            restart["message"] = (
                "restart pending — the last APPLY predates the installed plugin copy "
                "(the host has not loaded the current source)"
            )
    return {
        "repo": str(repo),
        "dsh_home": str(dsh_home),
        "plugin": {"path": str(plugin), "sha256": want, "mtime": plugin_mtime},
        "profiles": profiles,
        "ok": ok,
        "exit_code": 0 if ok else 1,
        "restart": restart,
    }


def main() -> int:
    ap = argparse.ArgumentParser(prog="harness_check.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent),
                    help="repository root holding dsh-plugin/index.js (default: the script's parent)")
    ap.add_argument("--dsh-home", default=str(Path.home() / ".dsh"),
                    help="DSH home holding profiles/*/plugins/ (default: ~/.dsh)")
    ap.add_argument("--json", action="store_true", help="emit the same facts as JSON")
    ns = ap.parse_args()
    result = collect(Path(ns.repo).resolve(), Path(ns.dsh_home).expanduser())
    if ns.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for p in result["profiles"]:
            print(f"profile {p['profile']}: {p['status']} ({p['path']})")
        if not result["profiles"]:
            print(f"no profiles under {result['dsh_home']}/profiles/*")
        restart = result["restart"]
        if restart["last_apply"]:
            print(f"last APPLY: {restart['last_apply']} (age {restart['age_seconds']}s)")
        if restart["message"]:
            print(("WARN: " if restart["warning"] else "note: ") + restart["message"])
        print("PASS" if result["ok"] else "FAIL")
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
