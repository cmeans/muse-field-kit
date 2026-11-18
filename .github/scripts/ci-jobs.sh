#!/usr/bin/env bash
# The ci-ok gate's logic, so its self-test covers all of it.
#
#   ci-jobs.sh list WORKFLOW.yml
#       Print the workflow's job ids, one per line, sorted.
#   ci-jobs.sh check WORKFLOW.yml GATE NEEDS_JSON
#       Exit 0 only when every job but GATE is in NEEDS_JSON (the gate's
#       `toJSON(needs)`) and each one's result is "success". Otherwise print
#       what's wrong and where to fix it, and exit 1.
#
# The workflow is read with yq (mikefarah's, v4: preinstalled on GitHub's
# Ubuntu runners), a real YAML parser, so the job list is the one GitHub
# sees: no line-based reading for a quoted key, a continued scalar or a
# decoy `jobs:` to get past. A file yq can't parse, a `jobs` that isn't a
# mapping with at least one job, and a job with `continue-on-error` (its
# failure would read as success in `needs`) are refused.
set -euo pipefail

usage() { echo "usage: ci-jobs.sh list WORKFLOW.yml | ci-jobs.sh check WORKFLOW.yml GATE NEEDS_JSON" >&2; exit 2; }

need_yq() {
  command -v yq >/dev/null 2>&1 || { echo "ci-jobs.sh: yq (mikefarah's, v4) is required" >&2; return 1; }
  yq --version 2>&1 | grep -q 'mikefarah' || { echo "ci-jobs.sh: yq is not mikefarah's yq v4: $(yq --version 2>&1)" >&2; return 1; }
}

list_jobs() {  # WORKFLOW
  local f=$1 kind jobs coe
  need_yq || return 1
  [ -r "$f" ] || { echo "ci-jobs.sh: cannot read $f" >&2; return 1; }
  kind=$(yq -r '.jobs | type' "$f" 2>&1) || { echo "ci-jobs.sh: yq can't parse $f: $kind" >&2; return 1; }
  [ "$kind" = '!!map' ] || { echo "ci-jobs.sh: $f has no jobs mapping (jobs is $kind)" >&2; return 1; }
  coe=$(yq -r '.jobs | to_entries | map(select(.value | has("continue-on-error"))) | .[].key' "$f")
  [ -z "$coe" ] || { echo "ci-jobs.sh: in $f, job-level continue-on-error on: $(printf '%s' "$coe" | paste -sd, - | sed 's/,/, /g'). A gated job's failure would read as success; remove it" >&2; return 1; }
  jobs=$(yq -r '.jobs | keys | .[]' "$f" | LC_ALL=C sort)
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs under jobs: in $f" >&2; return 1; }
  printf '%s\n' "$jobs"
}

check_gate() {  # WORKFLOW GATE NEEDS_JSON
  local f=$1 gate=$2 needs=$3 all jobs gated missing bad
  all=$(list_jobs "$f") || return 1
  jobs=$(printf '%s\n' "$all" | grep -vxF -- "$gate") || true
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs in $f besides $gate" >&2; return 1; }
  printf '%s' "$needs" | jq -e 'type == "object"' >/dev/null 2>&1 || { echo "ci-jobs.sh: NEEDS_JSON isn't a JSON object" >&2; return 1; }
  gated=$(printf '%s' "$needs" | jq -r 'keys[]' | LC_ALL=C sort)
  missing=$(LC_ALL=C comm -23 <(printf '%s\n' "$jobs") <(printf '%s\n' "$gated"))
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
