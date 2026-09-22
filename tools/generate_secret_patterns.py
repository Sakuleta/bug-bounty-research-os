#!/usr/bin/env python3
"""Render the unified secret-pattern source of truth into every implementation.

Source: tools/secret-patterns.json (one regex source per secret shape; only syntax
shared by Python `re` and JavaScript is allowed). Targets, rewritten between their
GENERATED markers (never hand-edit the blocks):

- tools/control_plane.py  ->  _SECRET_PATTERNS (re.compile(r"..."))
- dsh-plugin/index.js     ->  SECRET_SHAPES (/.../g)
- tools/bua/run.mjs       ->  SECRET_SHAPES (/.../g)

Run: python3 tools/generate_secret_patterns.py [--check] (exit 1 on drift).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = HERE / "secret-patterns.json"

TARGETS = (
    (REPO / "tools" / "control_plane.py", "#", '_SECRET_PATTERNS = [',
     lambda src: f'    re.compile(r"{src}"),'),
    (REPO / "dsh-plugin" / "index.js", "//", 'const SECRET_SHAPES = [',
     lambda src: f'  /{src}/g,'),
    (REPO / "tools" / "bua" / "run.mjs", "//", 'const SECRET_SHAPES = [',
     lambda src: f'  /{src}/g,'),
)


def load_sources() -> list[str]:
    doc = json.loads(SOURCE.read_text(encoding="utf-8"))
    patterns = doc.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("secret-patterns.json carries no patterns list")
    sources = []
    for entry in patterns:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("source"):
            raise ValueError(f"malformed pattern entry: {entry!r}")
        sources.append(str(entry["source"]))
    if len(set(sources)) != len(sources):
        raise ValueError("duplicate pattern sources in secret-patterns.json")
    return sources


def render(path: Path, comment: str, anchor: str, line: object, sources: list[str]) -> tuple[str, str]:
    text = path.read_text(encoding="utf-8")
    start_marker = f"{comment} BEGIN-GENERATED-SECRET-PATTERNS"
    end_marker = f"{comment} END-GENERATED-SECRET-PATTERNS"
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end < start:
        raise ValueError(f"{path}: GENERATED markers not found")
    head = text[: start + len(start_marker)]
    tail = text[end:]
    block = "\n".join(
        [head,
         f"{comment} Source of truth: tools/secret-patterns.json — do not hand-edit; "
         "run python3 tools/generate_secret_patterns.py.",
         anchor]
        + [line(src) for src in sources]
        + ["]"])
    return block, tail


def main() -> int:
    check = "--check" in sys.argv[1:]
    sources = load_sources()
    dirty = []
    for path, comment, anchor, line in TARGETS:
        block, tail = render(path, comment, anchor, line, sources)
        new_text = block + "\n" + tail
        if path.read_text(encoding="utf-8") != new_text:
            if check:
                dirty.append(str(path))
            else:
                path.write_text(new_text, encoding="utf-8")
                print(f"rendered {len(sources)} patterns into {path}")
    if dirty:
        print("secret-pattern drift (run python3 tools/generate_secret_patterns.py): "
              + ", ".join(dirty))
        return 1
    if check:
        print(f"secret patterns in sync ({len(sources)} shapes x 3 implementations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
