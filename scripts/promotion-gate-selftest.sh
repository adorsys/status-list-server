#!/usr/bin/env bash
set -euo pipefail

repo=$(mktemp -d)
fake_bin=$(mktemp -d)
trap 'rm -rf "$repo" "$fake_bin"' EXIT
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
cat > "$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$2" in
  */contents/Cargo.toml\?*) printf '%s\n' "$GATE_TEST_CARGO_CONTENT" ;;
  *) printf '%s\n' "$GATE_TEST_RUNS" ;;
esac
EOF
chmod +x "$fake_bin/gh"
export PATH="$fake_bin:$PATH"
export GATE_TEST_RUNS='{"workflow_runs":[]}'
export GATE_TEST_CARGO_CONTENT="$(base64 < "$repo/Cargo.toml" | tr -d '\n')"

run_gate() {
  local head_repository=${4:-$repo}
  local base_repository=${5:-$repo}
  bash scripts/promotion-gate.sh "$1" "$2" "$3" "$head_repository" "$base_repository" "$repo"
}

expect_pass() {
  if ! run_gate "$@" >/dev/null; then
    echo "::error::Promotion gate self-test expected pass: $*"
    exit 1
  fi
}

expect_fail() {
  local expected=$1
  shift
  local output
  if output=$(run_gate "$@" 2>&1); then
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
expect_fail "no matching validation run" main stage "$latest_sha"
expect_fail "v1.0.0-rc.2" main stage "$old_sha"
expect_fail "v1.0.0-rc.2" main stage "$(printf '0%.0s' {1..40})"

validation_run() {
  jq -cn --arg sha "$latest_sha" --arg status "$1" --arg conclusion "$2" \
    --arg branch "v1.0.0-rc.2" \
    '{workflow_runs:[{head_sha:$sha,head_branch:$branch,event:"push",status:$status,conclusion:$conclusion,run_number:1,html_url:"https://example.invalid/run/1"}]}'
}

GATE_TEST_RUNS=$(validation_run in_progress '')
export GATE_TEST_RUNS
expect_fail "in_progress" main stage "$latest_sha"
GATE_TEST_RUNS=$(validation_run completed failure)
export GATE_TEST_RUNS
expect_fail "failure" main stage "$latest_sha"
GATE_TEST_RUNS=$(validation_run completed success)
export GATE_TEST_RUNS
expect_pass main stage "$latest_sha"
GATE_TEST_RUNS=$(jq -cn --arg sha "$latest_sha" \
  '{workflow_runs:[{head_sha:$sha,head_branch:"v1.0.0-rc.2",event:"push",status:"completed",conclusion:"success",run_number:1,html_url:"https://example.invalid/run/1"},{head_sha:$sha,head_branch:"v1.0.0-rc.2",event:"push",status:"in_progress",conclusion:null,run_number:2,html_url:"https://example.invalid/run/2"}]}')
export GATE_TEST_RUNS
expect_fail "in_progress" main stage "$latest_sha"

GATE_TEST_RUNS=$(jq -cn --arg branch "v1.0.0-rc.2" \
  '{workflow_runs:[{head_sha:"wrong-sha",head_branch:$branch,event:"push",status:"completed",conclusion:"success",run_number:1,html_url:"https://example.invalid/run/1"},{head_sha:"wrong-sha",head_branch:"other-tag",event:"push",status:"completed",conclusion:"success",run_number:2,html_url:"https://example.invalid/run/2"},{head_sha:"wrong-sha",head_branch:$branch,event:"workflow_dispatch",status:"completed",conclusion:"success",run_number:3,html_url:"https://example.invalid/run/3"}]}')
export GATE_TEST_RUNS
expect_fail "no matching validation run" main stage "$latest_sha"

expect_fail "must come from the base repository" stage develop "$latest_sha" "fork/develop" "$repo"
expect_fail "must come from the base repository" main hotfix/security "$latest_sha" "fork/hotfix" "$repo"
GATE_TEST_RUNS=$(validation_run completed success)
export GATE_TEST_RUNS
expect_pass main hotfix/security "$latest_sha"

git -C "$repo" tag v1.0.0
expect_fail "already tagged as v1.0.0" main hotfix/security "$latest_sha"
sed -i 's/1.0.0/1.0.1/' "$repo/Cargo.toml"
GATE_TEST_CARGO_CONTENT="$(base64 < "$repo/Cargo.toml" | tr -d '\n')"
export GATE_TEST_CARGO_CONTENT
expect_pass main hotfix/security "$latest_sha"
expect_fail "must come from stage or hotfix" main develop "$latest_sha"

git -C "$repo" tag -d v1.0.0-rc.1 v1.0.0-rc.2 >/dev/null
expect_fail "No release candidate tag" main stage "$latest_sha"

echo "promotion gate self-test: all promotion cases passed"
