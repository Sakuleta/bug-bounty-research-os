#!/usr/bin/env python3
"""Live experiment: TypeSafe choice (supports/contradicts/says_nothing) on real rig evidence.

Guarded live runner: refuses to call the external API unless `--force` is passed AND
the `external_judgment` policy of the `--root` workspace is ALLOWED AND
`TYPESAFE_API_KEY` is set; output is written through a temp file + `os.replace`, and
the committed `claims_results.json` is never overwritten without `--force`.

The workspace is the one this experiment measured against: it must carry the evidence
refs E-000001, E-000002 and E-000004 (the registered captures). The original scratch
workspace no longer exists — the committed artifacts in tools/ts-eval/ are the
authoritative records (see README.md).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # tools/
from control_plane import external_judgment_allowed  # noqa: E402
from ts_claims import check_claims  # noqa: E402

SCRATCH = Path(__file__).resolve().parent

PACKET = {'claims': [
  {'id': 'c1', 'evidence_ref': 'E-000004', 'claim': 'The browser run completed with HTTP 200 against example.com.', 'expect': 'supports'},
  {'id': 'c2', 'evidence_ref': 'E-000004', 'claim': 'Before navigating, the runner reported a scope check against the engagement asset list.', 'expect': 'supports'},
  {'id': 'c3', 'evidence_ref': 'E-000004', 'claim': 'The runner did not start because of a provisioning error.', 'expect': 'contradicts'},
  {'id': 'c4', 'evidence_ref': 'E-000004', 'claim': 'The final page title was Login.', 'expect': 'contradicts'},
  {'id': 'c5', 'evidence_ref': 'E-000004', 'claim': 'The run validated a negative control.', 'expect': 'says_nothing'},
  {'id': 'c6', 'evidence_ref': 'E-000001', 'claim': 'The controlled HTTP request returned status 200.', 'expect': 'supports'},
  {'id': 'c7', 'evidence_ref': 'E-000001', 'claim': 'The response carried Cloudflare headers.', 'expect': 'supports'},
  {'id': 'c8', 'evidence_ref': 'E-000001', 'claim': 'The response body contained a login form.', 'expect': 'contradicts'},
  {'id': 'c9', 'evidence_ref': 'E-000002', 'claim': 'The browser attempt A-000007 was recorded although the runner never started.', 'expect': 'supports'},
  {'id': 'c10', 'evidence_ref': 'E-000002', 'claim': 'The token for A-000007 was consumed twice.', 'expect': 'says_nothing'},
]}


def default_root() -> Path:
    """Evidence + policy workspace: TS_EVAL_ROOT when set, else this repository."""
    return Path(os.environ.get('TS_EVAL_ROOT') or REPO_ROOT)


def guard_live(force: bool, root: Path) -> None:
    """Refuse a live run without --force and without an explicit policy opt-in."""
    if not force:
        raise SystemExit('claims_eval: refusing a live TypeSafe run without --force '
                         '(it calls the external API and rewrites the committed eval artifact)')
    if not external_judgment_allowed(root):
        raise SystemExit(f'claims_eval: external judgment denied by engagement policy '
                         f'({root / "00_control" / "engagement.yaml"}); set '
                         f'external_judgment: "ALLOWED" in the workspace passed as --root')
    if not os.environ.get('TYPESAFE_API_KEY'):
        raise SystemExit('TYPESAFE_API_KEY missing')


def write_results(path: Path, data, *, force: bool) -> bool:
    """Write `data` as JSON to `path` via temp file + os.replace, never overwriting the
    committed artifact without `--force`."""
    if path.exists() and not force:
        print(f'refusing to overwrite committed results without --force: {path}')
        return False
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as fh:
            fh.write(json.dumps(data, indent=2) + '\n')
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def run_live(root: Path) -> dict:
    out = check_claims(root, PACKET)
    expect = {c['id']: c['expect'] for c in PACKET['claims']}
    correct = 0
    for r in out['results']:
        ok = r['verdict'] == expect[r['id']]
        correct += ok
        print(f"{'OK ' if ok else 'MISS'} {r['id']:<4} expect={expect[r['id']]:<12} got={str(r['verdict']):<12} "
              f"conf={r['confidence']:.2f} auto={r['auto']} p_sup={r['probabilities'].get('supports', 0):.2f}")
    print(f"\naccuracy: {correct}/{len(out['results'])} | flagged for review: {out['summary']['flagged']} | model={out['model']}")
    print(f"tokens in/out: {out['usage']}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='claims_eval',
        description='Live TypeSafe claims-relation evaluation (guarded: needs --force and an ALLOWED policy).')
    ap.add_argument('--force', action='store_true',
                    help='required: call the external API and replace the committed result artifact')
    ap.add_argument('--root', default=None,
                    help='workspace whose evidence index and external_judgment policy this run uses '
                         '(default: TS_EVAL_ROOT, else this repo)')
    ns = ap.parse_args(argv)
    root = Path(ns.root) if ns.root else default_root()
    if not root.is_dir():
        raise SystemExit('--root must point to the workspace used for the claims experiment (see README.md)')
    guard_live(ns.force, root)
    out = run_live(root)
    write_results(SCRATCH / 'claims_results.json', out, force=ns.force)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
