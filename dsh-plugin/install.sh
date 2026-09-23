#!/usr/bin/env bash
# Install/update research-os-enforcer and its goal-deferral module into the local DSH
# profiles. Source of truth: this directory.
# Live copies: ~/.dsh/profiles/<profile>/plugins/research-os-enforcer/.
# A restart of the DSH host is required for a changed plugin body to load.
#
# Usage: ./install.sh [--dry-run]
#   --dry-run prints what it would copy and touches nothing.
#   DSH_PROFILES overrides the profile list (default: "web ro-smoke").
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
PROFILES="${DSH_PROFILES:-web ro-smoke}"
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
fi
for profile in $PROFILES; do
  DEST="$HOME/.dsh/profiles/$profile/plugins/research-os-enforcer"
  if [ "$DRY_RUN" = 1 ]; then
    echo "dry-run: would copy index.js package.json goal-deferral/*.js -> $DEST/"
    continue
  fi
  mkdir -p "$DEST/goal-deferral"
  cp "$SRC/index.js" "$SRC/package.json" "$DEST/"
  cp "$SRC/goal-deferral/"*.js "$DEST/goal-deferral/"
  echo "installed -> $DEST"
done
echo "next: restart the DSH host (plugin bodies load at startup), e.g. stop and re-run 'npx @deepseek-ai/dsh web'"
