#!/usr/bin/env bash
# Verify the Sigstore provenance GitHub issued for a pushed image digest.
# Usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]
# With git-ref the signer identity is pinned exactly; without, to any release tag.
# Needs gh >= 2.67.0 (older ones exit 0 with no attestation) and jq. See ADR 0001.
set -euo pipefail

# First gh release with the cli/cli#10418 fix.
readonly REQUIRED_GH_MAJOR=2
readonly REQUIRED_GH_MINOR=67
readonly PREDICATE_TYPE="https://slsa.dev/provenance/v1"
# deploy.yml signs, not CI.yml; attestation-selftest.sh checks this path still has the attest step.
readonly SIGNER_WORKFLOW_PATH=".github/workflows/deploy.yml"

# Includes prereleases, which promote-tags also publishes.
readonly RELEASE_REF_PATTERN='refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?'

# Retried: GitHub's API and Sigstore are separate failure domains. Only the delay is overridable.
readonly ATTEMPTS=3
retry_delay=${VERIFY_ATTESTATION_RETRY_DELAY:-5}

image_ref=${1:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]}
repo=${2:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]}
git_ref=${3:-}

# Digests only: a tag can move between this check and the pull.
# [[ =~ ]], not grep -Eq, which matches per line and would pass a valid first line.
if [[ ! "$image_ref" =~ ^[^[:space:]]+@(sha256:([a-f0-9]{64}))$ ]]; then
    echo "::error::'${image_ref}' is not an image reference pinned to a sha256 digest."
    echo "Verifying a tag would attest whatever that tag happens to resolve to at read time."
    exit 1
fi
digest="${BASH_REMATCH[1]}"
digest_hex="${BASH_REMATCH[2]}"

# Validated so a bad value fails with the right message, not a mismatched identity.
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

# Not piped into head -1: under pipefail, SIGPIPE would fail a healthy gh.
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

# Only . can be a regex metacharacter here, given the validation above.
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

reason=""

assert_verified() {
    local json json_type subjects
    # gh mixes progress lines into stdout, so start at the JSON array.
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
    # The causes need different fixes and only gh's output tells them apart, so print it.
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
