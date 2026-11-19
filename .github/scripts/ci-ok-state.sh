#!/usr/bin/env bash
# ci-ok-state.sh < CHECK_RUNS_JSON
# Reads a commit's check runs (the JSON of GET /repos/O/R/commits/SHA/check-runs)
# on stdin and prints the state of its newest "ci-ok" check run from GitHub
# Actions: "success", the conclusion of a finished run that didn't pass,
# "pending (<status>)", or "missing". Exits 0 only for "success".
set -euo pipefail

state=$(jq -r '
  [.check_runs[] | select(.name == "ci-ok" and .app.slug == "github-actions")]
  | sort_by(.id) | last
  | if . == null then "missing"
    elif .status != "completed" then "pending (\(.status))"
    else (.conclusion // "none") end')
printf '%s\n' "$state"
[ "$state" = success ]
