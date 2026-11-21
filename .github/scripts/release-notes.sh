#!/usr/bin/env bash
# release-notes.sh TAG CHANGELOG OUTFILE
# Checks the tag is exactly KIT-vX.Y.Z (KIT: lowercase letters, digits and
# single hyphens, such as credential-lockbox), that CHANGELOG is
# that kit's (its directory is named KIT), and that CHANGELOG has a
# "## X.Y.Z" heading (optionally followed by " — DATE ..."); writes that
# section's body to OUTFILE (the release notes). Prints the version on
# stdout. Writes nothing and exits 1 on any failure.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: release-notes.sh TAG CHANGELOG OUTFILE" >&2
  exit 2
fi
tag=$1
changelog=$2
outfile=$3
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! printf '%s\n' "$tag" | LC_ALL=C command grep -Eqx '[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+\.[0-9]+\.[0-9]+'; then
  echo "release-notes.sh: tag '$tag' is not KIT-vX.Y.Z (such as credential-lockbox-v1.2.3)" >&2
  exit 1
fi
kit=${tag%-v*}
version=${tag##*-v}
dir=$(basename "$(dirname "$changelog")")
if [ "$dir" != "$kit" ]; then
  echo "release-notes.sh: tag '$tag' is for kit '$kit', but $changelog is in '$dir'" >&2
  exit 1
fi

body=$("$here/changelog-section.sh" "$changelog" "$version")
mkdir -p "$(dirname "$outfile")"
printf '%s\n' "$body" >"$outfile"
printf '%s\n' "$version"
