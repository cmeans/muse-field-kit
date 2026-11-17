#!/usr/bin/env bash
# Print the body of the CHANGELOG section for a version: the lines after a
# heading "## X.Y.Z" (optionally followed by " — DATE ..." text, as in
# "## 0.1.0 — 2026-11-16 — first publication") up to the next "## " heading,
# with leading and trailing blank lines trimmed. Fails if the heading is
# missing or the section is empty.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: changelog-section.sh CHANGELOG VERSION" >&2
  exit 2
fi
file=$1
version=$2

body=$(tr -d '\r' <"$file" | awk -v h="## $version" '
  insec && /^## / { exit }
  insec { print; next }
  $0 == h || index($0, h " ") == 1 { insec = 1; found = 1 }
  END { exit !found }
') || { echo "changelog-section.sh: no '## $version' heading in $file" >&2; exit 1; }

# Trim leading and trailing blank lines.
body=$(printf '%s\n' "$body" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')
if [ -z "$body" ]; then
  echo "changelog-section.sh: the '## $version' section of $file is empty" >&2
  exit 1
fi
printf '%s\n' "$body"
