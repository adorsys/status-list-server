#!/usr/bin/env bash
set -euo pipefail

repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
git -C "$repo" config user.name "Gate Selftest"
git -C "$repo" config user.email "gate-selftest@example.invalid"
printf '[package]\nname = "gate-fixture"\nversion = "1.0.0"\n' > "$repo/Cargo.toml"
git -C "$repo" add Cargo.toml
git -C "$repo" commit -qm initial
old_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" tag v1.0.0-rc.1
printf '\n# next candidate\n' >> "$repo/Cargo.toml"
git -C "$repo" commit -qam next-candidate
latest_sha=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" tag v1.0.0-rc.2

expect_pass() {
  if ! bash scripts/promotion-gate.sh "$@" "$repo" >/dev/null; then
    echo "::error::Promotion gate self-test expected pass: $*"
    exit 1
  fi
}

expect_fail() {
  local expected=$1
  shift
  local output
  if output=$(bash scripts/promotion-gate.sh "$@" "$repo" 2>&1); then
    echo "::error::Promotion gate self-test expected failure: $*"
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "::error::Promotion gate self-test did not explain $expected. Output: $output"
    exit 1
  fi
}

expect_fail "must come from develop" stage feature "$latest_sha"
expect_pass stage develop "$latest_sha"
expect_pass main stage "$latest_sha"
expect_fail "v1.0.0-rc.2" main stage "$old_sha"
expect_fail "v1.0.0-rc.2" main stage "$(printf '0%.0s' {1..40})"
expect_pass main hotfix/security "$latest_sha"

git -C "$repo" tag v1.0.0
expect_fail "already tagged as v1.0.0" main hotfix/security "$latest_sha"
sed -i 's/1.0.0/1.0.1/' "$repo/Cargo.toml"
expect_pass main hotfix/security "$latest_sha"
expect_fail "must come from stage or hotfix" main develop "$latest_sha"

git -C "$repo" tag -d v1.0.0-rc.1 v1.0.0-rc.2 >/dev/null
expect_fail "No release candidate tag" main stage "$latest_sha"

echo "promotion gate self-test: all promotion cases passed"
