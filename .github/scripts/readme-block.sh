#!/usr/bin/env bash
# Print the fenced code block that sits between the markers
#   <!-- NAME:start -->  and  <!-- NAME:end -->
# in a Markdown file (each marker alone on its line). Used by CI to run the
# commands the docs give, so a doc change that breaks them fails CI.
# Fails if the marker pair is missing, unclosed, or holds no code.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: readme-block.sh FILE NAME" >&2
  exit 2
fi
file=$1
name=$2

# tr strips CR so a CRLF checkout still matches the markers.
out=$(tr -d '\r' <"$file" | awk -v s="<!-- $name:start -->" -v e="<!-- $name:end -->" '
  $0 == s { if (found) dup = 1; found = 1; inb = 1; next }
  $0 == e { if (inb) closed = 1; inb = 0; next }
  inb && /^```/ { fence = !fence; next }
  inb && fence { print }
  END { exit !(found && closed && !dup) }
') || { echo "readme-block.sh: marker pair '$name' missing, unclosed or duplicated in $file" >&2; exit 1; }

if [ -z "$out" ]; then
  echo "readme-block.sh: no code in the '$name' block of $file" >&2
  exit 1
fi
printf '%s\n' "$out"
