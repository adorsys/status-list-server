#!/usr/bin/env bash
# Verify the Sigstore-signed provenance GitHub issued for a pushed image digest.
#
# Usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]
#
#   <image-ref>  image reference pinned to a sha256 digest; tags are rejected.
#   <owner/repo> repository whose .github/workflows/deploy.yml must have signed it.
#   <git-ref>    optional; `refs/tags/v1.2.3` or `refs/heads/main`. Supplied, the signing
#                identity is pinned exactly (--cert-identity + --source-ref). Omitted,
#                it is pinned to a release-tag ref (end-anchored --cert-identity-regex).
#
# Requires gh >= 2.67.0 (older releases exit 0 when no attestation exists) and jq.
# The result is asserted from `--format json`, not from exit status or gh's output text.
#
# Background and rationale: docs/adr/0001-container-image-provenance.md.
set -euo pipefail

# The release the cli/cli#10418 fix shipped in, not the release the bug was reported
# against.
readonly REQUIRED_GH_MAJOR=2
readonly REQUIRED_GH_MINOR=67
readonly PREDICATE_TYPE="https://slsa.dev/provenance/v1"
# The workflow that carries the attest step, relative to the repository passed as $2.
# Composed from $2 rather than taken as an argument so the command in
# docs/supply-chain.md and the command the release path runs stay byte-identical. This is
# the workflow that *signs*, which is deploy.yml itself -- not CI.yml, which deploy.yml
# calls but which issues no attestation. scripts/attestation-selftest.sh asserts this
# path still exists and still contains the attest step, so moving that step turns a
# release-time failure that reads as "unsigned image" into a pull-request failure.
readonly SIGNER_WORKFLOW_PATH=".github/workflows/deploy.yml"

# A release-tag ref, for the regex used when the caller supplies no ref. Prereleases are
# included: `v*.*.*` accepts them and promote-tags publishes them.
readonly RELEASE_REF_PATTERN='refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?'

# Verification reaches GitHub's attestation API and Sigstore's trust root, which are
# separate failure domains from the registry. A blip must not fail a release, so the
# whole verification is retried. The delay is overridable so the self-test can drive the
# real retry loop without sleeping; the attempt count is not, so it cannot drive a
# different loop than the release path does.
readonly ATTEMPTS=3
retry_delay=${VERIFY_ATTESTATION_RETRY_DELAY:-5}

image_ref=${1:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]}
repo=${2:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]}
git_ref=${3:-}

# Arguments before tooling: a reference this script would refuse anyway is worth
# rejecting without requiring gh to be installed to find that out.
#
# Digest-pinned only. Verifying a tag proves that *something* carrying a valid
# attestation once answered to that name, which is not the question -- and the tag could
# resolve to a different digest between this check and the pull that follows it.
# `[[ =~ ]]` rather than `grep -Eq`, for the reason spelled out in
# scripts/resolve-arch-manifests.sh: grep matches line by line, so it would accept a
# value whose first line is a valid reference and whose second is anything at all.
if [[ ! "$image_ref" =~ ^[^[:space:]]+@(sha256:([a-f0-9]{64}))$ ]]; then
    echo "::error::'${image_ref}' is not an image reference pinned to a sha256 digest."
    echo "Verifying a tag would attest whatever that tag happens to resolve to at read time."
    exit 1
fi
digest="${BASH_REMATCH[1]}"
digest_hex="${BASH_REMATCH[2]}"

# Validated for the same reason as the reference: both are interpolated into the pinned
# identity below, and an identity built from a malformed repository would be a pattern
# nothing can match, which fails closed but reports the wrong cause.
if [[ ! "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    echo "::error::'${repo}' is not an <owner>/<repo> value."
    exit 1
fi

if [ -n "$git_ref" ] && [[ ! "$git_ref" =~ ^refs/[A-Za-z0-9._/-]+$ ]]; then
    echo "::error::'${git_ref}' is not a fully qualified git ref (expected refs/tags/... or refs/heads/...)."
    exit 1
fi

for tool in gh jq; do
    command -v "$tool" > /dev/null 2>&1 || {
        echo "::error::${tool} is required by $0 but was not found on PATH."
        exit 1
    }
done

# Captured whole and split in the shell rather than piped into `head -1`: `gh --version`
# prints a second line with the release URL, and under `pipefail` the early-exiting
# reader can SIGPIPE the writer, failing the pipeline on a gh that answered correctly.
version_raw=$(gh --version 2> /dev/null || true)
version_line=${version_raw%%$'\n'*}
if [[ ! "$version_line" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    echo "::error::could not read a version from 'gh --version'; refusing to guess whether it predates the cli/cli#10418 fix."
    echo "Got: '${version_line}'"
    exit 1
fi
gh_major=${BASH_REMATCH[1]}
gh_minor=${BASH_REMATCH[2]}

if ((gh_major < REQUIRED_GH_MAJOR || (gh_major == REQUIRED_GH_MAJOR && gh_minor < REQUIRED_GH_MINOR))); then
    echo "::error::gh ${gh_major}.${gh_minor} predates ${REQUIRED_GH_MAJOR}.${REQUIRED_GH_MINOR}, where 'gh attestation verify' still exited 0 on a missing attestation (cli/cli#10418)."
    echo "Verifying with it would report success for an image carrying no provenance at all."
    echo "Upgrade gh, then re-run."
    exit 1
fi

signer="https://github.com/${repo}/${SIGNER_WORKFLOW_PATH}"

# `.` is the only character the validated $repo and the literal path can contribute that
# is a regex metacharacter, so escaping it is sufficient. `-` is only special in a
# bracket expression.
identity_flags=()
if [ -n "$git_ref" ]; then
    identity_flags+=(--cert-identity "${signer}@${git_ref}" --source-ref "$git_ref")
    identity_description="${signer}@${git_ref}"
else
    signer_regex="^${signer//./\\.}@${RELEASE_REF_PATTERN}\$"
    identity_flags+=(--cert-identity-regex "$signer_regex")
    identity_description="${signer}@<a release tag>"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="${work}/stdout"
err="${work}/stderr"

# Set by assert_verified when it rejects, so the caller can report which of the several
# ways a result can be absent rather than successful actually occurred.
reason=""

assert_verified() {
    local json json_type subjects
    # gh prints progress lines to stdout alongside the JSON document, so the document is
    # taken from the first line that opens the array. A no-op when gh emits JSON only.
    json=$(sed -n '/^\[/,$p' "$out")
    if [ -z "$json" ]; then
        reason="gh exited 0 but produced no JSON result document"
        return 1
    fi
    if ! json_type=$(printf '%s\n' "$json" | jq -r 'type' 2> /dev/null) || [ "$json_type" != "array" ]; then
        reason="gh's JSON result is not the expected array document, so the schema this check reads has changed"
        return 1
    fi
    subjects=$(printf '%s\n' "$json" | jq -r '
        [ .[]?
          | .verificationResult.statement.subject[]?
          | .digest.sha256? // empty
        ] | unique | .[]?' 2> /dev/null || true)
    if [ -z "$subjects" ]; then
        reason="gh exited 0 but returned no verified attestation (this is the shape of cli/cli#10418)"
        return 1
    fi
    if ! printf '%s\n' "$subjects" | grep -Fxq "$digest_hex"; then
        reason="the verified attestation covers $(printf '%s' "$subjects" | tr '\n' ' '), not ${digest_hex}"
        return 1
    fi
    return 0
}

status=0
attempt=1
while :; do
    status=0
    : > "$out"
    : > "$err"
    gh attestation verify "oci://${image_ref}" \
        --repo "$repo" \
        "${identity_flags[@]}" \
        --predicate-type "$PREDICATE_TYPE" \
        --deny-self-hosted-runners \
        --format json > "$out" 2> "$err" || status=$?

    if [ "$status" -eq 0 ] && assert_verified; then
        break
    fi

    if [ "$attempt" -ge "$ATTEMPTS" ]; then
        break
    fi
    echo "attestation verification attempt ${attempt}/${ATTEMPTS} did not succeed; retrying."
    [ "$retry_delay" -eq 0 ] || sleep $((attempt * retry_delay))
    attempt=$((attempt + 1))
done

if [ "$status" -ne 0 ]; then
    echo "::error::no verifiable ${PREDICATE_TYPE} provenance from ${identity_description} for ${digest}."
    # Deliberately not asserting which of the several it was. An unreachable manifest, a
    # reachable one with no attestation, one signed by a different workflow and one
    # signed from a different ref all land here; they need different responses, and only
    # gh's output distinguishes them -- so it is printed rather than summarised.
    echo "Either the image could not be fetched, or nothing signed by ${identity_description} vouches for it."
    echo "A signature from another workflow, or from another ref of this one, fails here too, and that is"
    echo "deliberate: push access enough to forge an image is push access enough to dispatch a workflow."
    echo "gh's output below says which; docs/supply-chain.md 'When they disagree' covers the rest."
    cat "$err" "$out"
    exit 1
fi

if ! assert_verified; then
    echo "::error::gh exited 0 but the result does not verify ${digest}: ${reason}."
    echo "Treat the verification as not having happened."
    cat "$err" "$out"
    exit 1
fi

cat "$out"
echo "verified ${PREDICATE_TYPE} provenance from ${identity_description} for ${digest}"
