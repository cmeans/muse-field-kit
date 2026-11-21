#!/usr/bin/env bash
# Build the release asset set: copies the user's scripts (handoff.sh,
# handoff.ps1) and the agent's (agent-setup.sh, consume.py) from
# credential-lockbox/ into OUTDIR and writes
# OUTDIR/SHA256SUMS (sha256sum format, LF endings, sorted by name).
# Deterministic: the same tree gives the same bytes. Runs on Linux and macOS.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: release-assets.sh OUTDIR" >&2
  exit 2
fi
out=$1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
src="$root/credential-lockbox"
assets="agent-setup.sh consume.py handoff.ps1 handoff.sh" # sorted (LC_ALL=C), so SHA256SUMS is sorted

for f in $assets; do
  [ -f "$src/$f" ] || { echo "release-assets.sh: missing $src/$f" >&2; exit 1; }
done

mkdir -p "$out"
for f in $assets; do
  cp "$src/$f" "$out/$f"
done

if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$@"; }
else
  sum() { shasum -a 256 "$@"; }
fi

# From inside OUTDIR so the names carry no path; LC_ALL=C fixes the order.
(
  cd "$out"
  # shellcheck disable=SC2086  # $assets is a fixed, space-separated list
  sum $assets | LC_ALL=C sort -k 2 >SHA256SUMS
)
echo "wrote $out: $assets SHA256SUMS"
