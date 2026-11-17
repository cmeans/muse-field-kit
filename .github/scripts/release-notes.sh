#!/usr/bin/env bash
# release-notes.sh TAG CHANGELOG OUTFILE
# Checks the tag is exactly vX.Y.Z, that CHANGELOG has a "## X.Y.Z" heading
# (optionally followed by " — DATE ..."), and writes that section's body to
# OUTFILE (the release notes). Prints the version on stdout. Writes nothing
# and exits 1 on any failure.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: release-notes.sh TAG CHANGELOG OUTFILE" >&2
  exit 2
fi
tag=$1
changelog=$2
outfile=$3
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "release-notes.sh: tag '$tag' is not vX.Y.Z" >&2
  exit 1
fi
version=${tag#v}

body=$("$here/changelog-section.sh" "$changelog" "$version")
mkdir -p "$(dirname "$outfile")"
printf '%s\n' "$body" >"$outfile"
printf '%s\n' "$version"
