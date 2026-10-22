#!/usr/bin/env bash
# Prove verify-attestation.sh rejects what it should (eleven cases) and accepts the real thing (three).
# Uses a stubbed gh, so no network or registry. Run from the repo root.
set -euo pipefail

verifier=scripts/verify-attestation.sh

[ -f "$verifier" ] || {
    echo "::error::${verifier} is missing, so the release's provenance check is unverified."
    exit 1
}

signer_workflow=".github/workflows/deploy.yml"
[ -f "$signer_workflow" ] || {
    echo "::error::${signer_workflow} does not exist, but ${verifier} pins the signing identity to it."
    exit 1
}
grep -q 'actions/attest-build-provenance' "$signer_workflow" || {
    echo "::error::${signer_workflow} no longer contains the attest step."
    echo "The certificate SubjectAlternativeName is the job_workflow_ref of the job that signs, so"
    echo "moving that step to another workflow file silently invalidates every verification."
    echo "Update SIGNER_WORKFLOW_PATH in ${verifier} and this assertion together."
    exit 1
}
echo "attestation self-test: the signing workflow named by the verifier exists and attests"

digest_hex=$(printf 'a%.0s' $(seq 1 64))
other_hex=$(printf 'b%.0s' $(seq 1 64))
digest="sha256:${digest_hex}"
repo="adorsys/status-list-server"
image_ref="ghcr.io/adorsys/status-list-server@${digest}"
release_ref="refs/tags/v1.2.3"

# Absolute path: the no-gh case empties PATH, so env bash would fail and pass for the wrong reason.
bash_bin=$(command -v bash)

stub_dir=$(mktemp -d)
trap 'rm -rf "$stub_dir"' EXIT

cat > "${stub_dir}/gh" << 'STUB'
#!/bin/sh
if [ "$1" = "--version" ]; then
    printf '%s\n' "$STUB_VERSION"
    printf 'https://github.com/cli/cli/releases/tag/v0.0.0\n'
    exit 0
fi

if [ -n "${STUB_ARGV_FILE:-}" ]; then
    printf '%s\n' "$*" > "$STUB_ARGV_FILE"
fi

n=0
if [ -n "${STUB_COUNT_FILE:-}" ]; then
    [ -f "$STUB_COUNT_FILE" ] && n=$(cat "$STUB_COUNT_FILE")
    n=$((n + 1))
    printf '%s\n' "$n" > "$STUB_COUNT_FILE"
fi

for arg in "$@"; do
    case "$arg" in
        oci://*) printf 'Loaded digest %s for %s\n' "${arg##*@}" "$arg" ;;
    esac
done

if [ -n "${STUB_FAIL_FIRST:-}" ] && [ "$n" -le "$STUB_FAIL_FIRST" ]; then
    printf 'error connecting to api.github.com\n' >&2
    exit 1
fi

[ -z "${STUB_OUTPUT:-}" ] || printf '%s\n' "$STUB_OUTPUT"
[ -z "${STUB_JSON:-}" ] || printf '%s\n' "$STUB_JSON"
exit "$STUB_STATUS"
STUB
chmod +x "${stub_dir}/gh"

argv_file="${stub_dir}/argv"
count_file="${stub_dir}/count"

STUB_ARGV_FILE="$argv_file"
STUB_COUNT_FILE="$count_file"
STUB_FAIL_FIRST=""
STUB_JSON=""
VERIFY_ATTESTATION_RETRY_DELAY=0

export STUB_VERSION STUB_OUTPUT STUB_STATUS STUB_JSON STUB_ARGV_FILE STUB_COUNT_FILE \
    STUB_FAIL_FIRST VERIFY_ATTESTATION_RETRY_DELAY

CURRENT_VERSION="gh version 2.67.0 (2025-02-11)"

verified_json() {
    cat << JSON
[
  {
    "attestation": { "bundleUrl": "https://example.invalid/bundle" },
    "verificationResult": {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "statement": {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
          {
            "name": "ghcr.io/adorsys/status-list-server",
            "digest": { "sha256": "$1" }
          }
        ]
      }
    }
  }
]
JSON
}

reset_case() {
    rm -f "$argv_file" "$count_file"
    STUB_VERSION="$CURRENT_VERSION"
    STUB_STATUS=0
    STUB_OUTPUT=""
    STUB_JSON=""
    STUB_FAIL_FIRST=""
}

run_verifier() {
    PATH="${stub_dir}:${PATH}" "$verifier" "$@" 2>&1
}

expect_rejected() {
    description=$1
    shift
    if output=$(run_verifier "$@"); then
        echo "::error::attestation self-test passed against ${description}."
        echo "verify-attestation.sh cannot fail, so it is not protecting this release."
        echo "$output"
        exit 1
    fi
    echo "attestation self-test: ${description} correctly rejected"
}

expect_accepted() {
    description=$1
    shift
    if ! output=$(run_verifier "$@"); then
        echo "::error::attestation self-test rejected ${description}."
        echo "verify-attestation.sh blocks unconditionally and no release can pass it."
        echo "$output"
        exit 1
    fi
    echo "attestation self-test: ${description} correctly passes"
}

reset_case
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a tag-based image reference" \
    "ghcr.io/adorsys/status-list-server:latest-aws" "$repo"

reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a multi-line image reference" \
    "${image_ref}"$'\nghcr.io/attacker/evil:latest' "$repo"

reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a malformed owner/repo argument" "$image_ref" "not-a-repo"

reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a malformed git ref argument" "$image_ref" "$repo" "v1.2.3"

reset_case
if output=$(PATH="/nonexistent" "$bash_bin" "$verifier" "$image_ref" "$repo" 2>&1); then
    echo "::error::attestation self-test passed with no gh on PATH."
    echo "$output"
    exit 1
fi
echo "attestation self-test: a missing gh correctly rejected"

reset_case
STUB_VERSION="gh version 2.66.1 (2025-01-31)"
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a gh predating the cli/cli#10418 fix" "$image_ref" "$repo"

reset_case
STUB_VERSION="gh version unknown"
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a gh reporting an unparsable version" "$image_ref" "$repo"

reset_case
STUB_OUTPUT="✗ No attestations found for subject oci://${image_ref}"
expect_rejected "a gh exiting 0 having found no attestation (cli/cli#10418)" "$image_ref" "$repo"

reset_case
STUB_JSON="[]"
expect_rejected "a gh exiting 0 with an empty result array" "$image_ref" "$repo"

reset_case
STUB_JSON='[ {"verificationResult": '
expect_rejected "a gh whose JSON result cannot be parsed" "$image_ref" "$repo"

reset_case
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$other_hex")
expect_rejected "a verification covering a different digest" "$image_ref" "$repo"

reset_case
STUB_STATUS=1
STUB_OUTPUT="failed to verify attestation: no matching attestations found"
expect_rejected "a failed verification" "$image_ref" "$repo"

reset_case
STUB_OUTPUT="Loaded 1 attestation from GitHub API
✓ Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_accepted "a genuine verification pinned to a release ref" \
    "$image_ref" "$repo" "$release_ref"

[ -s "$argv_file" ] || {
    echo "::error::the gh stub recorded no arguments, so nothing about the invocation was checked."
    echo "Treat every invocation assertion below as not having run."
    exit 1
}
recorded=$(cat "$argv_file")

assert_argv() {
    case "$recorded" in
        *"$1"*) echo "attestation self-test: the verifier passes ${2}" ;;
        *)
            echo "::error::verify-attestation.sh did not pass '${1}'."
            echo "${3}"
            echo "gh was called with: ${recorded}"
            exit 1 ;;
    esac
}

assert_argv "--repo ${repo}" "--repo" \
    "Without it, attestation lookup is not scoped to this repository."
assert_argv "--cert-identity https://github.com/${repo}/.github/workflows/deploy.yml@${release_ref}" \
    "an exact --cert-identity when the ref is known" \
    "Without an exactly pinned SubjectAlternativeName, an attestation signed by this workflow from any
branch verifies -- and build-and-push runs on workflow_dispatch, so producing one needs only
repository write access. See docs/adr/0001-container-image-provenance.md §Consequences."
assert_argv "--source-ref ${release_ref}" "--source-ref" \
    "This is the independent certificate-extension check on the ref; it is additive to the SAN match."
assert_argv "--predicate-type https://slsa.dev/provenance/v1" "--predicate-type" \
    "Without it, any predicate type would satisfy the check."
assert_argv "--deny-self-hosted-runners" "--deny-self-hosted-runners" \
    "Every job here runs on GitHub-hosted runners, so a self-hosted signature is by definition not ours."
assert_argv "--format json" "--format json" \
    "The result is asserted from the JSON document; gh's prose echoes back the digest it was handed."

case "$recorded" in
    *--signer-workflow*)
        echo "::error::verify-attestation.sh passed --signer-workflow alongside --cert-identity."
        echo "gh resolves SAN/SANRegex first and returns before reading SignerWorkflow, so the flag is"
        echo "silently ignored. Pass exactly one identity flag; see the header of ${verifier}."
        echo "gh was called with: ${recorded}"
        exit 1 ;;
    *) echo "attestation self-test: the verifier does not pass a silently-ignored --signer-workflow" ;;
esac

reset_case
STUB_OUTPUT="✓ Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_accepted "a genuine verification with no ref supplied" "$image_ref" "$repo"

recorded=$(cat "$argv_file")
expected_regex='--cert-identity-regex ^https://github\.com/adorsys/status-list-server/\.github/workflows/deploy\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
case "$recorded" in
    *"$expected_regex"*)
        echo "attestation self-test: the verifier anchors the identity regex at both ends" ;;
    *)
        echo "::error::verify-attestation.sh did not pass the end-anchored identity regex."
        echo "expected to contain: ${expected_regex}"
        echo "gh was called with:  ${recorded}"
        echo "An unanchored regex admits sibling workflow paths such as deploy.yml-staging.yml,"
        echo "and an unpinned ref admits any branch. See the header of ${verifier}."
        exit 1 ;;
esac

reset_case
STUB_FAIL_FIRST=2
STUB_OUTPUT="✓ Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_accepted "a verification that succeeds after two transient failures" \
    "$image_ref" "$repo" "$release_ref"
attempts_made=$(cat "$count_file")
if [ "$attempts_made" -ne 3 ]; then
    echo "::error::the verifier called gh ${attempts_made} times, expected 3."
    echo "Either it is not retrying, or it is retrying a different number of times than the"
    echo "release path would. A transient API failure would fail a release."
    exit 1
fi
echo "attestation self-test: a transient failure is retried, and the retry is bounded at 3"

echo "attestation self-test: all cases passed"
