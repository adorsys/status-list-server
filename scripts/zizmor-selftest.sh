#!/usr/bin/env bash
# Proves the workflow scanner still fails the build when it finds something.
#
# A green zizmor job has two possible causes: the workflows are clean, or the gate
# stopped reporting. Those are indistinguishable from the outside, and this repository
# has already shipped the second one -- the job ran as `zizmor ... || true` for long
# enough that 84 findings accumulated behind a check that could not fail.
#
# So assert the negative case directly: run the pinned scanner against a workflow with
# a known finding and require it to fail.
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

# 13 is zizmor's exit code for "findings at or above the failure threshold". 0 means it
# found nothing in a file that definitely contains something; anything else is a crash
# or a usage error. All of those mean the gate is not doing its job.
if [ "$status" -ne 13 ]; then
  echo "::error::expected zizmor to exit 13 on the known-bad fixture, got ${status}."
  echo "The workflow security gate may no longer fail on findings -- do not trust a"
  echo "green zizmor job until this passes again."
  echo
  echo "$output"
  exit 1
fi

# Exit code alone would also be satisfied by some unrelated finding appearing in the
# fixture, so check it failed for the reason the fixture encodes.
if ! printf '%s\n' "$output" | grep -q 'artipacked'; then
  echo "::error::zizmor failed on the fixture, but not with the expected artipacked finding."
  echo "Either the fixture drifted or the artipacked audit changed."
  echo
  echo "$output"
  exit 1
fi

echo "self-test passed: zizmor exits ${status} on a workflow with a known finding."
