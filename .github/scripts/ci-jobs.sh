#!/usr/bin/env bash
# The ci-ok gate's logic, so its self-test covers all of it.
#
#   ci-jobs.sh list WORKFLOW.yml
#       Print the workflow's job names, one per line, sorted: the keys under
#       `jobs:`, two spaces in, as this repo writes them.
#   ci-jobs.sh check WORKFLOW.yml GATE NEEDS_JSON
#       Exit 0 only when every job but GATE is in NEEDS_JSON (the gate's
#       `toJSON(needs)`) and each one's result is "success". Otherwise print
#       what's wrong and where to fix it, and exit 1.
#
# `list` fails closed: a line under `jobs:` it doesn't read is an error,
# never a job left out. Accepted job keys: `  name:`, `  "name":` and
# `  'name':`, each with an optional trailing `# comment`. Lines indented
# further (a job's body) and blank or comment lines are skipped. Refused: a
# key with a value on its line (flow style), a tab, one space or three
# spaces of indent, CRLF line ends, no `jobs:`, a job named twice, and any
# line at column 0 after `jobs:` (`jobs:` must be the file's last top-level
# key: a column-0 line inside it, such as a quoted scalar continued there,
# could otherwise hide the jobs after it).
set -euo pipefail

usage() { echo "usage: ci-jobs.sh list WORKFLOW.yml | ci-jobs.sh check WORKFLOW.yml GATE NEEDS_JSON" >&2; exit 2; }

list_jobs() {  # WORKFLOW
  local f=$1 out jobs dups
  [ -r "$f" ] || { echo "ci-jobs.sh: cannot read $f" >&2; return 1; }
  if LC_ALL=C grep -q $'\r' "$f"; then
    echo "ci-jobs.sh: $f has CRLF line ends" >&2; return 1
  fi
  out=$(LC_ALL=C awk '
    /^jobs:[ ]*(#.*)?$/ { in_jobs = 1; seen = 1; next }
    !in_jobs { next }
    /^[ ]*(#.*)?$/ { next }                    # blank or comment
    /^[^ ]/ { print "BAD " NR ": " $0; next }  # column 0 after jobs:
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
      next
    }
    /^ [^ ]/ || /^   [^ ]/ || /^[ ]*\t/ { print "BAD " NR ": " $0 }
    END { if (!seen) print "NOJOBS" }
  ' "$f")
  if printf '%s\n' "$out" | grep -q '^NOJOBS$'; then
    echo "ci-jobs.sh: no jobs: key in $f" >&2; return 1
  fi
  if printf '%s\n' "$out" | grep -q '^BAD '; then
    echo "ci-jobs.sh: in $f, a line under jobs: that isn't a job key this script reads. Write each job as '  name:' (two spaces, nothing after the colon but a comment), and keep jobs: the last top-level key:" >&2
    printf '%s\n' "$out" | sed -n 's/^BAD /  line /p' >&2
    return 1
  fi
  jobs=$(printf '%s\n' "$out" | sed '/^$/d' | sort)
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs under jobs: in $f" >&2; return 1; }
  dups=$(printf '%s\n' "$jobs" | uniq -d)
  [ -z "$dups" ] || { echo "ci-jobs.sh: in $f, a job named twice: $dups" >&2; return 1; }
  printf '%s\n' "$jobs"
}

check_gate() {  # WORKFLOW GATE NEEDS_JSON
  local f=$1 gate=$2 needs=$3 all jobs gated missing bad
  all=$(list_jobs "$f") || return 1
  jobs=$(printf '%s\n' "$all" | grep -vxF -- "$gate") || true
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs in $f besides $gate" >&2; return 1; }
  gated=$(printf '%s' "$needs" | jq -r 'keys[]' | sort) || { echo "ci-jobs.sh: NEEDS_JSON isn't a JSON object" >&2; return 1; }
  missing=$(comm -23 <(printf '%s\n' "$jobs") <(printf '%s\n' "$gated"))
  if [ -n "$missing" ]; then
    echo "ci-jobs.sh: $gate doesn't need these jobs, so they aren't gated: $(printf '%s' "$missing" | paste -sd, - | sed 's/,/, /g'). Add them to $gate's needs: in $f" >&2
    return 1
  fi
  printf '%s' "$needs" | jq -r 'to_entries[] | "\(.key): \(.value.result)"'
  bad=$(printf '%s' "$needs" | jq -r '[to_entries[] | select(.value.result != "success") | .key] | join(", ")')
  if [ -n "$bad" ]; then
    echo "ci-jobs.sh: not every CI job passed: $bad" >&2
    return 1
  fi
}

[ $# -ge 1 ] || usage
case $1 in
  list) [ $# -eq 2 ] || usage; list_jobs "$2" ;;
  check) [ $# -eq 4 ] || usage; check_gate "$2" "$3" "$4" ;;
  *) usage ;;
esac
