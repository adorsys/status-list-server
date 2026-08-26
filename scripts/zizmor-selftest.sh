#!/usr/bin/env bash
# Asserts the workflow scanner still fails on a finding. A clean repo and a broken
# gate both look green; this repo already shipped the second, as `zizmor ... || true`.
set -euo pipefail

fixture="$(cd "$(dirname "$0")" && pwd)/testdata/zizmor-selftest-workflow.yml"

if [ ! -f "$fixture" ]; then
  echo "::error::self-test fixture missing: ${fixture}"
  exit 1
fi

set +e
output=$(zizmor --persona regular --no-online-audits --format plain "$fixture" 2>&1)
status=$?
set -e

# 13 = findings at or above the failure threshold.
if [ "$status" -ne 13 ]; then
  echo "::error::expected zizmor to exit 13 on the known-bad fixture, got ${status}."
  echo "The workflow security gate may no longer fail on findings -- do not trust a"
  echo "green zizmor job until this passes again."
  echo
  echo "$output"
  exit 1
fi

# An unrelated finding would satisfy the exit code alone.
if ! printf '%s\n' "$output" | grep -q 'artipacked'; then
  echo "::error::zizmor failed on the fixture, but not with the expected artipacked finding."
  echo "Either the fixture drifted or the artipacked audit changed."
  echo
  echo "$output"
  exit 1
fi

echo "self-test passed: zizmor exits ${status} on a workflow with a known finding."
