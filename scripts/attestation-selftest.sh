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
# the same assertions the release path uses, driven through six cases. Five must be
# rejected and one must pass, because a verifier that rejects unconditionally is equally
# broken and would otherwise only surface mid-release, on the last step before a deploy.
#
# The `#10418 replay` case is the one that earns this file. It reproduces gh 2.66.1's
# behaviour exactly -- exit 0, with "no attestations found" on stdout and no digest
# anywhere in it. A verifier that checked only the exit status would pass that, and an
# image carrying no provenance at all would be reported as verified by the very command
# documented as the defence. That bug is fixed upstream; this is the assertion that it
# stays fixed here, and that a future rewrite of the verifier cannot quietly reintroduce
# the shape of it.
#
# Needs no network, no image, no registry and no real gh: every case is a shell stub
# parameterised by three environment variables. Run from the repository root; takes no
# arguments.
set -euo pipefail

verifier=scripts/verify-attestation.sh

[ -f "$verifier" ] || {
    echo "::error::${verifier} is missing, so the release's provenance check is unverified."
    exit 1
}

# A digest of the right shape but no significance: nothing here reaches a registry, and
# the point of the fixture is that the verifier echoes back exactly what it was handed.
digest="sha256:$(printf 'a%.0s' $(seq 1 64))"
image_ref="ghcr.io/adorsys/status-list-server@${digest}"
repo="adorsys/status-list-server"

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
printf '%s\n' "$STUB_OUTPUT"
exit "$STUB_STATUS"
STUB
chmod +x "${stub_dir}/gh"

export STUB_VERSION STUB_OUTPUT STUB_STATUS

CURRENT_VERSION="gh version 2.67.0 (2025-02-11)"

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

# A tag, not a digest. Rejected on the argument alone, before gh is consulted at all.
STUB_VERSION="$CURRENT_VERSION"
STUB_STATUS=0
STUB_OUTPUT="Verification succeeded! ${digest}"
expect_rejected "a tag-based image reference" \
    "ghcr.io/adorsys/status-list-server:latest-aws" "$repo"

# The version floor, and the case that proves it is load-bearing: this stub claims a
# successful verification *and* names the digest, so every other assertion in the
# verifier passes it. Only the floor can catch it.
STUB_VERSION="gh version 2.66.1 (2025-01-31)"
STUB_STATUS=0
STUB_OUTPUT="Verification succeeded! ${digest} was attested."
expect_rejected "a gh predating the cli/cli#10418 fix" "$image_ref" "$repo"

# An unreadable version is not evidence of a fixed gh, so it must not be treated as one.
STUB_VERSION="gh version unknown"
STUB_STATUS=0
STUB_OUTPUT="Verification succeeded! ${digest} was attested."
expect_rejected "a gh reporting an unparseable version" "$image_ref" "$repo"

# The #10418 replay. Exit 0, no digest in the output.
STUB_VERSION="$CURRENT_VERSION"
STUB_STATUS=0
STUB_OUTPUT="No attestations found with predicate type: https://slsa.dev/provenance/v1"
expect_rejected "a gh exiting 0 having found no attestation (cli/cli#10418)" "$image_ref" "$repo"

# An ordinary verification failure: a real gh rejecting a real image.
STUB_VERSION="$CURRENT_VERSION"
STUB_STATUS=1
STUB_OUTPUT="failed to verify attestation: no matching attestations found"
expect_rejected "a failed verification" "$image_ref" "$repo"

# The other direction. A verifier that blocks unconditionally is equally broken, and
# would otherwise only surface during a release, after the image had already been built.
STUB_VERSION="$CURRENT_VERSION"
STUB_STATUS=0
STUB_OUTPUT=$(printf 'Loaded 1 attestation from GitHub API\nVerification succeeded!\n\n%s was attested by:\n%s  https://slsa.dev/provenance/v1' "$digest" "$repo")
if ! output=$(run_verifier "$image_ref" "$repo"); then
    echo "::error::attestation self-test rejected a well-formed successful verification."
    echo "verify-attestation.sh blocks unconditionally and no release can pass it."
    echo "$output"
    exit 1
fi
echo "attestation self-test: a genuine verification correctly passes"
