#!/usr/bin/env python3
"""Tests for tools/harness_check.py against a fake DSH home. No dependencies.

Run: python3 tools/test_harness_check.py (exits non-zero on failure).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
CHECK = TOOLS / "harness_check.py"
INSTALL = REPO / "dsh-plugin" / "install.sh"
PLUGIN = REPO / "dsh-plugin" / "index.js"
DEFERRAL = REPO / "dsh-plugin" / "goal-deferral" / "index.js"

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CHECK), *args], capture_output=True, text=True)


def fake_home(profiles: dict[str, bytes | None], log: str | None = None,
              deferrals: dict[str, bytes | None] | None = None) -> Path:
    """Fake DSH home: profile -> plugin bytes (None = no plugin file).

    `deferrals` maps profile -> goal-deferral/index.js bytes; profiles default to the
    repo copy, `None` omits the file.
    """
    overrides = deferrals or {}
    home = Path(tempfile.mkdtemp(prefix="dsh-home-"))
    for name, payload in profiles.items():
        plugin_dir = home / "profiles" / name / "plugins" / "research-os-enforcer"
        if payload is None:
            (home / "profiles" / name).mkdir(parents=True, exist_ok=True)
            continue
        plugin_dir.mkdir(parents=True, exist_ok=True)
        (plugin_dir / "index.js").write_bytes(payload)
        deferral_payload = overrides.get(name, DEFERRAL_SOURCE)
        if deferral_payload is not None:
            (plugin_dir / "goal-deferral").mkdir(parents=True, exist_ok=True)
            (plugin_dir / "goal-deferral" / "index.js").write_bytes(deferral_payload)
    if log is not None:
        (home / "research-os-enforcer.log").write_text(log)
    return home


SOURCE = PLUGIN.read_bytes()
DEFERRAL_SOURCE = DEFERRAL.read_bytes()
DRIFTED = SOURCE + b"\n// drifted local copy\n"
DEFERRAL_DRIFTED = DEFERRAL_SOURCE + b"\n// drifted local copy\n"
APPLY_OLD = "2020-01-01T00:00:00.000Z APPLY ok\n"
APPLY_FRESH = "2999-01-01T00:00:00.000Z APPLY ok\n"

# 1. Matching plugin -> OK, exit 0.
home = fake_home({"web": SOURCE}, log=APPLY_FRESH)
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("a matching plugin reports OK and exits 0",
      r.returncode == 0 and "web" in r.stdout and "OK" in r.stdout)

# 2. Missing plugin -> MISSING, and with no OK profile the check fails.
home = fake_home({"web": None})
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("a missing plugin reports MISSING and exits 1",
      r.returncode == 1 and "web" in r.stdout and "MISSING" in r.stdout)

# 3. Drifted sha -> DRIFT + exit 1 even when another profile is OK.
home = fake_home({"web": SOURCE, "ro-smoke": DRIFTED})
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("a drifted plugin reports DRIFT and exits 1",
      r.returncode == 1 and "ro-smoke" in r.stdout and "DRIFT" in r.stdout
      and "web" in r.stdout and "OK" in r.stdout)

# 4. One OK profile and one MISSING profile still passes (presence, not completeness).
home = fake_home({"web": SOURCE, "retired": None})
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("at least one OK profile with none DRIFT passes",
      r.returncode == 0 and "MISSING" in r.stdout)

# 5. Log older than the plugin file -> restart-pending warning (exit stays 0).
home = fake_home({"web": SOURCE}, log=APPLY_OLD)
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("an APPLY older than the plugin warns that a restart is pending",
      r.returncode == 0 and "restart" in r.stdout.lower() and "2020-01-01" in r.stdout)

# 6. --json emits the same facts.
home = fake_home({"web": SOURCE, "ro-smoke": DRIFTED}, log=APPLY_OLD)
r = run("--repo", str(REPO), "--dsh-home", str(home), "--json")
data = json.loads(r.stdout)
check("--json reports per-profile status and the runner's exit code",
      r.returncode == 1 and data["ok"] is False and data["exit_code"] == 1
      and {p["profile"]: p["status"] for p in data["profiles"]} == {"web": "OK", "ro-smoke": "DRIFT"}
      and data["plugin"]["sha256"] == hashlib.sha256(SOURCE).hexdigest()
      and data["restart"]["warning"])

# 7. No profiles at all: nothing is OK, so the check exits 1.
empty = Path(tempfile.mkdtemp(prefix="dsh-empty-"))
r = run("--repo", str(REPO), "--dsh-home", str(empty))
check("a dsh-home with no profiles fails (nothing is OK)",
      r.returncode == 1 and "no profiles" in r.stdout)


# 8. The restart comparison is against the INSTALLED profile copy's mtime, never the
# repo file's: both files sharing "now" cannot tell the two rules apart, so pin the
# three mtimes apart. A future-dated installed copy with an old repo file must warn; a
# backdated installed copy with a newer repo file must not.
def dated_repo(mtime: float) -> Path:
    repo = Path(tempfile.mkdtemp(prefix="fake-repo-"))
    (repo / "dsh-plugin" / "goal-deferral").mkdir(parents=True)
    path = repo / "dsh-plugin" / "index.js"
    path.write_bytes(SOURCE)
    os.utime(path, (mtime, mtime))
    (repo / "dsh-plugin" / "goal-deferral" / "index.js").write_bytes(DEFERRAL_SOURCE)
    return repo


future = time.time() + 3600
past = time.time() - 10 * 365 * 24 * 3600
old_repo = dated_repo(past)
home = fake_home({"web": SOURCE}, log="2021-01-01T00:00:00.000Z APPLY ok\n")
installed = home / "profiles/web/plugins/research-os-enforcer/index.js"
os.utime(installed, (future, future))
r = run("--repo", str(old_repo), "--dsh-home", str(home), "--json")
data = json.loads(r.stdout)
check("the restart warning fires against the installed copy's mtime, not the repo file's",
      data["restart"]["warning"] is True
      and abs(data["restart"]["installed_mtime"] - installed.stat().st_mtime) < 1)
new_repo = dated_repo(time.time())
home2 = fake_home({"web": SOURCE}, log="2026-01-01T00:00:00.000Z APPLY ok\n")
installed2 = home2 / "profiles/web/plugins/research-os-enforcer/index.js"
installed2_deferral = home2 / "profiles/web/plugins/research-os-enforcer/goal-deferral/index.js"
os.utime(installed2, (past, past))
os.utime(installed2_deferral, (past, past))
r = run("--repo", str(new_repo), "--dsh-home", str(home2), "--json")
data = json.loads(r.stdout)
check("a backdated installed copy does not warn even when the repo file is newer",
      data["restart"]["warning"] is False)

# 9. The goal-deferral module is part of the installed body: missing or drifted is
#    not OK, so the deferral path can never silently rot behind a current index.js.
home = fake_home({"web": SOURCE}, deferrals={"web": None})
r = run("--repo", str(REPO), "--dsh-home", str(home))
check("a missing goal-deferral module reports MISSING and exits 1",
      r.returncode == 1 and "MISSING" in r.stdout and "goal-deferral" in r.stdout)
home = fake_home({"web": SOURCE}, deferrals={"web": DEFERRAL_DRIFTED})
r = run("--repo", str(REPO), "--dsh-home", str(home), "--json")
data = json.loads(r.stdout)
check("a drifted goal-deferral module reports DRIFT and exits 1",
      r.returncode == 1 and data["profiles"][0]["status"] == "DRIFT"
      and data["profiles"][0]["deferral_status"] == "DRIFT"
      and data["plugin"]["deferral"]["sha256"] == hashlib.sha256(DEFERRAL_SOURCE).hexdigest())

# 10. install.sh --dry-run: prints the plan, touches nothing.
home = Path(tempfile.mkdtemp(prefix="dsh-install-dry-"))
r = subprocess.run(["bash", str(INSTALL), "--dry-run"],
                   capture_output=True, text=True,
                   env={**os.environ, "HOME": str(home), "DSH_PROFILES": "web ro-smoke"})
check("install.sh --dry-run names both profiles and writes nothing",
      r.returncode == 0 and "dry-run" in r.stdout and "web" in r.stdout
      and "ro-smoke" in r.stdout and not (home / ".dsh").exists())

# 11. install.sh then harness_check: the install rows are green end to end.
home = Path(tempfile.mkdtemp(prefix="dsh-install-"))
r = subprocess.run(["bash", str(INSTALL)],
                   capture_output=True, text=True,
                   env={**os.environ, "HOME": str(home), "DSH_PROFILES": "web ro-smoke"})
check("install.sh installs the enforcer and the goal-deferral module into both profiles",
      r.returncode == 0 and "installed -> " + str(home / ".dsh/profiles/web") in r.stdout
      and (home / ".dsh/profiles/web/plugins/research-os-enforcer/goal-deferral/index.js").is_file()
      and (home / ".dsh/profiles/ro-smoke/plugins/research-os-enforcer/goal-deferral/index.js").is_file())
r = run("--repo", str(REPO), "--dsh-home", str(home / ".dsh"), "--json")
data = json.loads(r.stdout)
check("harness_check reports every installed profile OK after install.sh",
      r.returncode == 0 and data["ok"] is True
      and {p["profile"]: p["status"] for p in data["profiles"]} == {"web": "OK", "ro-smoke": "OK"})

print(f"\n{len(passed)}/{len(passed)} passed")
