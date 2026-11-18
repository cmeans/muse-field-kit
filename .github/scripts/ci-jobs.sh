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
# The workflow is read with yq (mikefarah's, 4.25 or newer: preinstalled on
# GitHub's Ubuntu runners), a real YAML parser, with aliases expanded, so
# the job list is the one GitHub sees: no line-based reading for a quoted
# key, a continued scalar or a decoy `jobs:` to get past. A file yq can't
# parse, a `jobs` that isn't a mapping with at least one job, and a job with
# `continue-on-error` (its failure would read as success in `needs`) are
# refused. Each error says what to do; under GitHub Actions, ci-ok's steps
# turn its last line into the run's error annotation.
set -euo pipefail

usage() { echo "usage: ci-jobs.sh list WORKFLOW.yml | ci-jobs.sh check WORKFLOW.yml GATE NEEDS_JSON" >&2; exit 2; }

# Tested OK on 4.25.3 through 4.54.3; 4.20.2 and older reject -r.
YQ_MIN=4.25
need_tools() {
  local v
  command -v jq >/dev/null 2>&1 || { echo "ci-jobs.sh: jq is required (preinstalled on GitHub's Ubuntu runners; if the image dropped it, add an install step to ci-ok)" >&2; return 1; }
  command -v yq >/dev/null 2>&1 || { echo "ci-jobs.sh: mikefarah's yq ${YQ_MIN} or newer is required (preinstalled on GitHub's Ubuntu runners; if the image dropped it, add a step to ci-ok that installs a pinned mikefarah/yq release binary, checked by its sha256)" >&2; return 1; }
  v=$(yq --version 2>&1 | grep -oE 'mikefarah.*version v?[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+$') || true
  if [ -z "$v" ] || ! printf '%s\n%s\n' "$YQ_MIN" "$v" | sort -V -C; then
    echo "ci-jobs.sh: need mikefarah's yq ${YQ_MIN} or newer; found: $(yq --version 2>&1 | head -n 1)" >&2; return 1
  fi
}

# Every query starts with explode(.), so a job written as a YAML alias is
# read with what it points to (GitHub supports anchors and aliases).
list_jobs() {  # WORKFLOW
  local f=$1 kind jobs coe
  need_tools || return 1
  [ -r "$f" ] || { echo "ci-jobs.sh: cannot read $f" >&2; return 1; }
  kind=$(yq -r 'explode(.) | .jobs | type' "$f" 2>&1) || { echo "ci-jobs.sh: yq can't parse $f: $kind" >&2; return 1; }
  [ "$kind" = '!!map' ] || { echo "ci-jobs.sh: $f has no jobs mapping (jobs is $kind)" >&2; return 1; }
  coe=$(yq -r 'explode(.) | .jobs | to_entries | map(select(.value | has("continue-on-error"))) | .[].key' "$f")
  [ -z "$coe" ] || { echo "ci-jobs.sh: in $f, job-level continue-on-error on: $(printf '%s' "$coe" | paste -sd, - | sed 's/,/, /g'). A gated job's failure would read as success; remove it" >&2; return 1; }
  jobs=$(yq -r 'explode(.) | .jobs | keys | .[]' "$f" | LC_ALL=C sort)
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs under jobs: in $f" >&2; return 1; }
  printf '%s\n' "$jobs"
}

check_gate() {  # WORKFLOW GATE NEEDS_JSON
  local f=$1 gate=$2 needs=$3 all jobs gated missing bad
  all=$(list_jobs "$f") || return 1
  printf '%s\n' "$all" | grep -qxF -- "$gate" || { echo "ci-jobs.sh: no job named $gate in $f (the gate job's id; the steps pass it as github.job)" >&2; return 1; }
  jobs=$(printf '%s\n' "$all" | grep -vxF -- "$gate") || true
  [ -n "$jobs" ] || { echo "ci-jobs.sh: no jobs in $f besides $gate" >&2; return 1; }
  printf '%s' "$needs" | jq -e 'type == "object"' >/dev/null 2>&1 || { echo "ci-jobs.sh: NEEDS_JSON isn't a JSON object (the steps pass toJSON(needs))" >&2; return 1; }
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
