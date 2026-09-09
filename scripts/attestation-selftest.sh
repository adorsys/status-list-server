#!/usr/bin/env bash
# Prove scripts/verify-attestation.sh can fail, before a release is allowed to trust it.
#
# A release whose attestation verifies is the expected result on every run, and that is
# the problem: a verifier that has never rejected anything is indistinguishable from one
# that cannot reject anything. Both print a success line and exit zero. This is the same
# argument scripts/gate-selftest.sh makes for the vulnerability gate, applied to the
# check that the vulnerability gate's sibling -- provenance -- is real.
#
# So the verifier is run against a stubbed `gh` placed first on PATH: the same script and
# the same assertions the release path uses. Eleven cases must be rejected and three must
# pass, because a verifier that rejects unconditionally is equally broken and would
# otherwise only surface mid-release, on the last step before a deploy.
#
# The stub's output is a faithful reproduction of the real thing, and that is load
# bearing rather than tidiness. Real `gh attestation verify` prints
#
#     Loaded digest <digest> for oci://<ref>
#
# to stdout *before* it fetches anything, echoing back the digest it was handed. An
# earlier revision of the verifier asserted "the output names the digest" as its defence
# against cli/cli#10418, and a stub that omitted this line made that assertion look like
# it worked. Against real gh it is satisfied unconditionally and proves nothing. So the
# stub emits the line on every case, including the #10418 replay -- which means a
# verifier that regressed to a text assertion is *rejected here*, and the assertion that
# actually holds (an empty JSON result cannot come from a successful verification) is the
# one being exercised.
#
# The invocation assertions are about argv rather than outcome. Be precise about why they
# take that shape. Whether `gh` honours a flag is `gh`'s contract, and a stub cannot
# demonstrate it -- a stub that "rejected a signature from another workflow" would only
# prove the stub was written to reject it, which is a test proving something other than
# what it claims. What is ours to get wrong is which flags are sent, and one of those is
# a trap: `newEnforcementCriteria` reads `SANRegex`/`SAN` *before* `SignerWorkflow` and
# returns early, so passing `--signer-workflow` alongside `--cert-identity` would leave
# the former silently ignored. Its *absence* is therefore asserted too.
#
# Needs no network, no image, no registry and no real gh: every case is a shell stub
# parameterised by environment variables. Run from the repository root; takes no
# arguments.
set -euo pipefail

verifier=scripts/verify-attestation.sh

[ -f "$verifier" ] || {
    echo "::error::${verifier} is missing, so the release's provenance check is unverified."
    exit 1
}

# The verifier pins the signing identity to this path. If the attest step moves, the
# certificate SAN stops matching and every release fails with a message that reads
# "unsigned image" -- the most misleading possible symptom, discovered at the worst
# possible time. Asserted here so the move fails on the pull request that makes it.
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

# A digest of the right shape but no significance: nothing here reaches a registry, and
# the point of the fixture is that the verifier matches what gh reports back against what
# it was handed.
digest_hex=$(printf 'a%.0s' $(seq 1 64))
other_hex=$(printf 'b%.0s' $(seq 1 64))
digest="sha256:${digest_hex}"
repo="adorsys/status-list-server"
image_ref="ghcr.io/adorsys/status-list-server@${digest}"
release_ref="refs/tags/v1.2.3"

bash_bin=$(command -v bash)

stub_dir=$(mktemp -d)
trap 'rm -rf "$stub_dir"' EXIT

# One stub, parameterised by the environment, rather than one per case: a case that
# differs from the real thing in some way its author did not intend is how a self-test
# comes to prove something other than what it claims.
cat > "${stub_dir}/gh" << 'STUB'
#!/bin/sh
if [ "$1" = "--version" ]; then
    printf '%s\n' "$STUB_VERSION"
    # The real `gh --version` prints a release URL on a second line. Reproduced because
    # the verifier has to survive it without SIGPIPE-ing itself.
    printf 'https://github.com/cli/cli/releases/tag/v0.0.0\n'
    exit 0
fi

# Recorded after the --version branch, so the file holds the `attestation verify`
# invocation rather than the version probe that precedes it.
if [ -n "${STUB_ARGV_FILE:-}" ]; then
    printf '%s\n' "$*" > "$STUB_ARGV_FILE"
fi

n=0
if [ -n "${STUB_COUNT_FILE:-}" ]; then
    [ -f "$STUB_COUNT_FILE" ] && n=$(cat "$STUB_COUNT_FILE")
    n=$((n + 1))
    printf '%s\n' "$n" > "$STUB_COUNT_FILE"
fi

# Faithful reproduction of real gh: the artifact it was handed is echoed back on stdout
# before any attestation is fetched. Every case emits this, so no assertion in the
# verifier may depend on it.
for arg in "$@"; do
    case "$arg" in
        oci://*) printf 'Loaded digest %s for %s\n' "${arg##*@}" "$arg" ;;
    esac
done

# A transient API failure, for the retry case. Counted invocations only.
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
# The retry loop is exercised for real; only the sleeping is removed, so the self-test
# cannot pass against a verifier whose retry behaviour differs from the release path's.
VERIFY_ATTESTATION_RETRY_DELAY=0

export STUB_VERSION STUB_OUTPUT STUB_STATUS STUB_JSON STUB_ARGV_FILE STUB_COUNT_FILE \
    STUB_FAIL_FIRST VERIFY_ATTESTATION_RETRY_DELAY

CURRENT_VERSION="gh version 2.67.0 (2025-02-11)"

# A well-formed result document, in the shape gh's `--format json` exporter produces:
# an array of processing results, each carrying the in-toto statement it verified.
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

# ---------------------------------------------------------------------------------
# Rejected before gh is consulted at all.

# A tag, not a digest.
reset_case
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a tag-based image reference" \
    "ghcr.io/adorsys/status-list-server:latest-aws" "$repo"

# A reference whose *first* line is valid and whose second is anything at all. This is
# the case the verifier's `[[ =~ ]]` (rather than `grep -Eq`) exists for: grep matches
# line by line and would accept it.
reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a multi-line image reference" \
    "${image_ref}"$'\nghcr.io/attacker/evil:latest' "$repo"

# The repository argument is interpolated into the pinned identity, so a malformed one
# would build a pattern nothing can match: it fails closed, but reports the wrong cause.
reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a malformed owner/repo argument" "$image_ref" "not-a-repo"

reset_case
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a malformed git ref argument" "$image_ref" "$repo" "v1.2.3"

# ---------------------------------------------------------------------------------
# Rejected because the tooling cannot be trusted to answer.

# `bash` by absolute path: with PATH emptied, `#!/usr/bin/env bash` could not resolve an
# interpreter, and the test would pass for the wrong reason.
reset_case
if output=$(PATH="/nonexistent" "$bash_bin" "$verifier" "$image_ref" "$repo" 2>&1); then
    echo "::error::attestation self-test passed with no gh on PATH."
    echo "$output"
    exit 1
fi
echo "attestation self-test: a missing gh correctly rejected"

# The version floor, and the case that proves it is load-bearing: this stub claims a
# successful verification, names the digest, *and* returns a well-formed result document,
# so every other assertion in the verifier passes it. Only the floor can catch it.
reset_case
STUB_VERSION="gh version 2.66.1 (2025-01-31)"
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a gh predating the cli/cli#10418 fix" "$image_ref" "$repo"

# An unreadable version is not evidence of a fixed gh, so it must not be treated as one.
reset_case
STUB_VERSION="gh version unknown"
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_rejected "a gh reporting an unparsable version" "$image_ref" "$repo"

# ---------------------------------------------------------------------------------
# Rejected because the result is absent rather than successful. These are the cases the
# file exists for.

# The #10418 replay: exit 0, no attestation, and -- crucially -- the digest *is* present
# in the output, because gh echoed back what it was handed. A verifier asserting on the
# text passes this. Only the JSON assertion rejects it.
reset_case
STUB_OUTPUT="✗ No attestations found for subject oci://${image_ref}"
expect_rejected "a gh exiting 0 having found no attestation (cli/cli#10418)" "$image_ref" "$repo"

# The same shape, expressed as an empty result array rather than as no document at all.
reset_case
STUB_JSON="[]"
expect_rejected "a gh exiting 0 with an empty result array" "$image_ref" "$repo"

# A schema change must block a release loudly rather than degrade the check silently.
reset_case
STUB_JSON='[ {"verificationResult": '
expect_rejected "a gh whose JSON result cannot be parsed" "$image_ref" "$repo"

# The digest binding: a well-formed, successful verification of some *other* artifact.
# This is what the discarded text assertion could never have caught, because the digest
# it looked for was echoed back regardless of what was verified.
reset_case
STUB_OUTPUT="Verification succeeded!"
STUB_JSON=$(verified_json "$other_hex")
expect_rejected "a verification covering a different digest" "$image_ref" "$repo"

# An ordinary verification failure: a real gh rejecting a real image.
reset_case
STUB_STATUS=1
STUB_OUTPUT="failed to verify attestation: no matching attestations found"
expect_rejected "a failed verification" "$image_ref" "$repo"

# ---------------------------------------------------------------------------------
# Accepted. A verifier that blocks unconditionally is equally broken, and would
# otherwise only surface during a release, after the image had already been built.

reset_case
STUB_OUTPUT="Loaded 1 attestation from GitHub API
✓ Verification succeeded!"
STUB_JSON=$(verified_json "$digest_hex")
expect_accepted "a genuine verification pinned to a release ref" \
    "$image_ref" "$repo" "$release_ref"

# The argv of the run immediately above -- the real release-path invocation, not a
# synthetic one. Checked for existence first: a missing file means the stub was never
# reached, and an absent recording must not read as a satisfied assertion.
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
repository write access. See the header of scripts/verify-attestation.sh."
assert_argv "--source-ref ${release_ref}" "--source-ref" \
    "This is the independent certificate-extension check on the ref; it is additive to the SAN match."
assert_argv "--predicate-type https://slsa.dev/provenance/v1" "--predicate-type" \
    "Without it, any predicate type would satisfy the check."
assert_argv "--deny-self-hosted-runners" "--deny-self-hosted-runners" \
    "Every job here runs on GitHub-hosted runners, so a self-hosted signature is by definition not ours."
assert_argv "--format json" "--format json" \
    "The result is asserted from the JSON document; gh's prose echoes back the digest it was handed."

# The absence assertion. gh's newEnforcementCriteria checks SANRegex/SAN before
# SignerWorkflow and returns early, so passing both would leave --signer-workflow
# silently ignored while looking like a second layer of pinning.
case "$recorded" in
    *--signer-workflow*)
        echo "::error::verify-attestation.sh passed --signer-workflow alongside --cert-identity."
        echo "gh resolves SAN/SANRegex first and returns before reading SignerWorkflow, so the flag is"
        echo "silently ignored. Pass exactly one identity flag; see the header of ${verifier}."
        echo "gh was called with: ${recorded}"
        exit 1 ;;
    *) echo "attestation self-test: the verifier does not pass a silently-ignored --signer-workflow" ;;
esac

# The other identity form: no ref supplied, so the SAN is matched by a regex anchored at
# *both* ends. Written as a literal rather than rebuilt from the verifier's parts -- a
# test that mirrors the construction it is checking would accept any construction.
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

# The retry loop. GitHub's attestation API and Sigstore's trust root are separate failure
# domains from the registry, and a blip must not fail a release on the last step before a
# deploy. Two transient failures then a success; the invocation count proves the retry
# happened rather than the first call having quietly succeeded.
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
