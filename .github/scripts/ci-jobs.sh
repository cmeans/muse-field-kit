#!/usr/bin/env bash
# Print the job names of a workflow file, one per line, sorted: the keys
# under `jobs:`, two spaces in, as this repo writes them.
#
#   ci-jobs.sh WORKFLOW.yml
#
# ci-ok uses it to check that it needs every job. It fails closed: a job key
# in a form it doesn't parse (flow style, a key on a line with a value, a
# tab, CRLF line ends, another indent) is an error, never a job left out.
# Accepted: `  name:`, `  "name":` and `  'name':`, each with an optional
# trailing `# comment`. Blank lines and comment lines are skipped.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: ci-jobs.sh WORKFLOW.yml" >&2; exit 2; }
f=$1
[ -r "$f" ] || { echo "ci-jobs.sh: cannot read $f" >&2; exit 1; }
if LC_ALL=C grep -q $'\r' "$f"; then
  echo "ci-jobs.sh: $f has CRLF line ends" >&2; exit 1
fi

out=$(LC_ALL=C awk '
  /^jobs:[ ]*(#.*)?$/ { in_jobs = 1; seen = 1; next }
  !in_jobs { next }
  /^[ ]*(#.*)?$/ { next }                    # blank or comment
  /^[^ ]/ { exit }                           # the next top-level key
  /^  [^ ]/ {
    line = $0
    sub(/^  /, "", line)
    if (match(line, /^"[A-Za-z0-9_-]+"[ ]*:[ ]*(#.*)?$/) ||
        match(line, /^'\''[A-Za-z0-9_-]+'\''[ ]*:[ ]*(#.*)?$/) ||
        match(line, /^[A-Za-z0-9_-]+[ ]*:[ ]*(#.*)?$/)) {
      sub(/[ ]*:.*$/, "", line)
      gsub(/["'\'']/, "", line)
      print line
      next
    }
    print "BAD " NR ": " $0
    bad = 1
    next
  }
  /^ [^ ]/ || /^\t/ { print "BAD " NR ": " $0; bad = 1 }
  END { if (!seen) print "NOJOBS" }
' "$f")

if printf '%s\n' "$out" | grep -q '^NOJOBS$'; then
  echo "ci-jobs.sh: no jobs: key in $f" >&2; exit 1
fi
if printf '%s\n' "$out" | grep -q '^BAD '; then
  echo "ci-jobs.sh: a line under jobs: that isn't a job key this script reads (write it as '  name:'):" >&2
  printf '%s\n' "$out" | sed -n 's/^BAD //p' >&2
  exit 1
fi
jobs=$(printf '%s\n' "$out" | sed '/^$/d' | sort)
[ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs under jobs: in $f" >&2; exit 1; }
dups=$(printf '%s\n' "$jobs" | uniq -d)
[ -z "$dups" ] || { echo "ci-jobs.sh: a job named twice: $dups" >&2; exit 1; }
printf '%s\n' "$jobs"
