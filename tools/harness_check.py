#!/usr/bin/env python3
"""Presence check for the installed research-os-enforcer DSH plugin.

For every `<dsh-home>/profiles/*/plugins/research-os-enforcer/` compare the sha256 of
`index.js` and of the `goal-deferral/index.js` module with the repo's copies and
report OK / MISSING / DRIFT (a profile is OK only when both files match: the veto
module is part of the installed body). Also read `<dsh-home>/research-os-enforcer.log`
and report the last `APPLY` line's age, warning when it predates the newest INSTALLED
copy that reported OK (the host was not restarted after the last install; the repo
file's mtime says nothing about what the host loaded).
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
DEFERRAL_REL = Path("dsh-plugin") / "goal-deferral" / "index.js"
PROFILE_DEFERRAL_REL = Path("plugins") / "research-os-enforcer" / "goal-deferral" / "index.js"
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


def file_status(got: str | None, want: str | None) -> str:
    if got is None:
        return "MISSING"
    if want is not None and got == want:
        return "OK"
    return "DRIFT"


def collect(repo: Path, dsh_home: Path) -> dict:
    plugin = repo / PLUGIN_REL
    deferral = repo / DEFERRAL_REL
    want = sha256_file(plugin)
    want_deferral = sha256_file(deferral)

    def stat_mtime(path: Path) -> float | None:
        try:
            return path.stat().st_mtime
        except OSError:
            return None

    profiles = []
    for profile_dir in sorted((dsh_home / "profiles").glob("*")):
        installed = profile_dir / PROFILE_PLUGIN_REL
        installed_deferral = profile_dir / PROFILE_DEFERRAL_REL
        index_status = file_status(sha256_file(installed), want)
        deferral_status = file_status(sha256_file(installed_deferral), want_deferral)
        # A profile is OK only when the whole installed body matches: the deferral
        # module is part of it, and a stale copy is an unenforced deferral path.
        if index_status == "OK" and deferral_status == "OK":
            status = "OK"
        elif "MISSING" in (index_status, deferral_status):
            status = "MISSING"
        else:
            status = "DRIFT"
        profiles.append({
            "profile": profile_dir.name,
            "path": str(installed),
            "status": status,
            "index_status": index_status,
            "sha256": sha256_file(installed),
            "mtime": stat_mtime(installed),
            "deferral_path": str(installed_deferral),
            "deferral_status": deferral_status,
            "deferral_sha256": sha256_file(installed_deferral),
            "deferral_mtime": stat_mtime(installed_deferral),
        })
    worst = "none" if not profiles else (
        "DRIFT" if any(p["status"] == "DRIFT" for p in profiles)
        else ("OK" if any(p["status"] == "OK" for p in profiles) else "MISSING"))
    ok = any(p["status"] == "OK" for p in profiles) and worst != "DRIFT"

    # The load-bearing comparison: what the host actually loaded is the INSTALLED copy,
    # so the newest OK install's mtime is the one an APPLY must postdate. The repo
    # file's mtime is irrelevant to the running host. Both installed files load at
    # startup, so the newest of either decides.
    installed_mtimes = [mtime for p in profiles if p["status"] == "OK"
                        for mtime in (p["mtime"], p["deferral_mtime"]) if mtime is not None]
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
        "plugin": {"path": str(plugin), "sha256": want, "mtime": stat_mtime(plugin),
                   "deferral": {"path": str(deferral), "sha256": want_deferral,
                                "mtime": stat_mtime(deferral)}},
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
            if p["deferral_status"] != p["index_status"]:
                print(f"  goal-deferral: {p['deferral_status']} ({p['deferral_path']})")
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
