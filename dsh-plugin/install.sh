#!/usr/bin/env bash
# Install/update research-os-enforcer into the local DSH web profile.
# Source of truth: this directory. Live copy: ~/.dsh/profiles/web/plugins/research-os-enforcer/.
# A restart of the DSH host is required for a changed plugin body to load.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.dsh/profiles/web/plugins/research-os-enforcer"
mkdir -p "$DEST"
cp "$SRC/index.js" "$SRC/package.json" "$DEST/"
echo "installed -> $DEST"
echo "next: restart the DSH host (plugin bodies load at startup), e.g. stop and re-run 'npx @deepseek-ai/dsh web'"
