#!/usr/bin/env bash
# Verify the Sigstore-signed provenance GitHub issued for a pushed image digest.
#
# This answers "who built this", which BuildKit's own provenance cannot. The
# `provenance: mode=max` attestation deploy.yml attaches is integrity-protected -- the
# index digest chain covers it, so it cannot be altered without changing the digest --
# but its `builder.id` is self-asserted: it is JSON BuildKit wrote, with nothing binding
# it to the run that allegedly produced it. Anyone with push access to the GHCR package
# can push an index carrying a fabricated provenance manifest that inspects identically.
# The statement `actions/attest-build-provenance` issues is a separate document with a
# Fulcio identity behind it, and this is the check that the identity is really there.
#
# Both documents are kept on purpose; docs/adr/0001-container-image-provenance.md is the
# decision and says which one a consumer should verify for which question.
#
# Two failure modes are guarded, and the second is why this is a script.
#
# `gh attestation verify` exited 0 when it found *no* attestation until gh 2.67.0
# (cli/cli#10418, fixed by #10421). That is the absence-reads-as-success failure this
# repository is organised against, occurring inside the command documented as the
# defence against it -- a laptop or runner carrying an older gh would report a clean
# verification for an image with no provenance at all. So the floor is enforced here
# rather than assumed.
#
# Exit status alone is not sufficient evidence even on a fixed gh. A missing binary, an
# unreachable API and a revoked identity all exit non-zero, and a regression of #10418
# would exit zero again, so this also asserts the output names the digest it was given.
# Only a verification that really resolved this artifact can echo it back. Same
# reasoning as scripts/gate-selftest.sh, and scripts/attestation-selftest.sh proves both
# directions of it against a stubbed gh.
#
# A script rather than an inline step so the release path, the self-test and the command
# in docs/supply-chain.md are provably the same check. Same reasoning as
# scripts/vuln-gate.sh: three copies would drift, and a documented command that has
# drifted from the enforced one tells a consumer nothing about the enforced one.
#
# Usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo>
set -euo pipefail

# The release the fix shipped in, not the release the bug was reported against.
readonly REQUIRED_GH_MAJOR=2
readonly REQUIRED_GH_MINOR=67
readonly PREDICATE_TYPE="https://slsa.dev/provenance/v1"

image_ref=${1:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo>}
repo=${2:?usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo>}

# Arguments before tooling: a reference this script would refuse anyway is worth
# rejecting without requiring gh to be installed to find that out.
#
# Digest-pinned only. Verifying a tag proves that *something* carrying a valid
# attestation once answered to that name, which is not the question -- and the tag could
# resolve to a different digest between this check and the pull that follows it.
# `[[ =~ ]]` rather than `grep -Eq`, for the reason spelled out in
# scripts/resolve-arch-manifests.sh: grep matches line by line, so it would accept a
# value whose first line is a valid reference and whose second is anything at all.
if [[ ! "$image_ref" =~ ^[^[:space:]]+@(sha256:[a-f0-9]{64})$ ]]; then
    echo "::error::'${image_ref}' is not an image reference pinned to a sha256 digest."
    echo "Verifying a tag would attest whatever that tag happens to resolve to at read time."
    exit 1
fi
digest="${BASH_REMATCH[1]}"

command -v gh > /dev/null 2>&1 || {
    echo "::error::gh is required by $0 but was not found on PATH."
    exit 1
}

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

status=0
output=$(gh attestation verify "oci://${image_ref}" \
    --repo "$repo" \
    --predicate-type "$PREDICATE_TYPE" 2>&1) || status=$?

if [ "$status" -ne 0 ]; then
    echo "::error::no verifiable ${PREDICATE_TYPE} provenance from ${repo} for ${digest}."
    # Deliberately not asserting which of the two it was. An unreachable manifest and a
    # reachable one with no attestation both land here, they need different responses,
    # and only gh's output distinguishes them -- so it is printed rather than summarised.
    echo "Either the image could not be fetched, or nothing signed by a ${repo} workflow vouches for it."
    echo "gh's output below says which; docs/supply-chain.md 'When they disagree' covers the second case."
    echo "$output"
    exit 1
fi

# The #10418 assertion, and the reason a bare exit-status check is not enough: a gh that
# exits 0 without having resolved this artifact cannot print its digest.
case "$output" in
    *"$digest"*) ;;
    *)
        echo "::error::gh exited 0 but never named ${digest}, so nothing about this image was verified."
        echo "This is the shape of cli/cli#10418. Treat the verification as not having happened."
        echo "$output"
        exit 1 ;;
esac

echo "$output"
echo "verified ${PREDICATE_TYPE} provenance from ${repo} for ${digest}"
