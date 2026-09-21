#!/usr/bin/env python3
"""Thin wrapper: new_cycle.py <ENGAGEMENT_DIR> <CYCLE_ID> -> cycle.py create."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cycle import cmd_create  # noqa: E402

if len(sys.argv) != 3:
    print('usage: new_cycle.py <ENGAGEMENT_DIR> <CYCLE_ID>')
    raise SystemExit(2)

try:
    cmd_create(Path(sys.argv[1]).resolve(), sys.argv[2])
except SystemExit as e:
    raise SystemExit(e.code if isinstance(e.code, int) else 1)
