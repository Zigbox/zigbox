#!/usr/bin/env bash
# Decides whether demo-m6d runs (ci.yml's demo-m6d job, vm.yml's vm/m6d-* branches). It runs only
# with the owner's Google setup, the repository variables of docs/demos/m6d.md, and with an OIDC
# token to exchange, which the runner offers only to a job with `id-token: write` and never to a
# fork's pull request. Writes `run=true|false` to $GITHUB_OUTPUT (stdout when unset); for false,
# prints one line saying why, and adds it to the job summary. Never fails: a missing setup is a
# demo not run, not a failed one.
#
# Environment: FORK ("true" for a fork's pull request) and the variables named below. Prints
# names only, never a value.
set -euo pipefail

output=${GITHUB_OUTPUT:-/dev/stdout}

skip() {
  local line="demo-m6d: NOT RUN: $1 (setup: docs/demos/m6d.md)"
  echo "$line"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$line" >> "$GITHUB_STEP_SUMMARY"; fi
  echo "run=false" >> "$output"
  exit 0
}

if [ "${FORK:-false}" = true ]; then skip "a fork's pull request gets no OIDC token"; fi
# ZBX_GAR_SERVICE_ACCOUNT is optional: without it the federated identity reads directly.
for name in ZBX_GAR_PROVIDER ZBX_GAR_REGISTRY ZBX_GCR_REGISTRY; do
  if [ -z "${!name:-}" ]; then skip "the repository variable $name is not set"; fi
done
for name in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN; do
  if [ -z "${!name:-}" ]; then skip "$name is not set (the job needs id-token: write)"; fi
done
echo "run=true" >> "$output"
