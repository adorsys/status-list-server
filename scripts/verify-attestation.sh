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
# Usage: verify-attestation.sh <image-ref@sha256:...> <owner/repo> [<git-ref>]
#
#   <git-ref>  optional; `refs/tags/v1.2.3` or `refs/heads/main`. Supplied, the signing
#              identity is pinned exactly. Omitted, it is pinned to the shape of a
#              release tag. See "Pinning the identity" below.
#
# ---------------------------------------------------------------------------------
# Pinning the identity
#
# The certificate's SubjectAlternativeName is the `job_workflow_ref` of the job that
# signed: `https://github.com/<owner>/<repo>/.github/workflows/deploy.yml@<ref>`. Three
# things about it have to be pinned, and the obvious flag pins only one and a half.
#
# `--repo` alone scopes attestation *lookup*, so it establishes only that *some*
# workflow in this repository signed the digest. That is weaker in exactly the direction
# that matters: the threat is push access, and whoever can publish a forged image can
# also add a workflow that signs it.
#
# `--signer-workflow` is the documented answer to that and is not sufficient either.
# gh turns it into `"^" + regexp.QuoteMeta("https://<host>/<owner>/<repo>/<path>")`
# (cli/cli pkg/cmd/attestation/verify/policy.go, validateSignerWorkflow) -- a regex
# anchored at the *start only*. Two consequences:
#
#   1. The `@<ref>` suffix is unconstrained. `build-and-push` is not tag-gated -- it runs
#      on `workflow_dispatch` -- so anyone with repository write access can dispatch this
#      very workflow from a branch carrying a modified Dockerfile and receive a genuinely
#      signed attestation over their image. It would verify. Dispatching the workflow
#      that already exists is *easier* than adding one, so `--signer-workflow` closes the
#      wrong half of the hole it is documented as closing.
#   2. A prefix match admits sibling paths: `.github/workflows/deploy.yml-staging.yml`
#      matches `^...deploy\.yml`.
#
# So the identity is pinned with `--cert-identity` (exact string) when the caller knows
# the ref, and with an end-anchored `--cert-identity-regex` when it does not. Note that
# these are not additive with `--signer-workflow`: `newEnforcementCriteria` checks
# `opts.SANRegex || opts.SAN` *first* and returns before it ever looks at SignerWorkflow,
# so passing both would silently ignore the latter. Only one is passed, deliberately.
#
# `--source-ref` is an independent certificate extension check rather than a SAN match,
# so it is additive, and is passed as well when the ref is known.
#
# `--deny-self-hosted-runners` is always passed: every job in this repository runs on
# GitHub-hosted runners, so an attestation from a self-hosted runner is by definition not
# ours.
#
# ---------------------------------------------------------------------------------
# Why the result is read as JSON rather than as gh's output text
#
# Exit status alone is not sufficient evidence: a missing binary, an unreachable API and
# a revoked identity all exit non-zero, and `gh attestation verify` exited *0* when it
# found no attestation at all until gh 2.67.0 (cli/cli#10418, fixed by #10421) -- the
# absence-reads-as-success failure this repository is organised against, occurring inside
# the command documented as the defence against it. The version floor below is enforced
# rather than assumed for that reason, and the result is asserted on top of it.
#
# That assertion reads `--format json`, not the human-readable output, because the
# obvious text assertion does not work. gh prints
#
#     Loaded digest %s for %s
#
# to stdout *before* it fetches anything (cli/cli pkg/cmd/attestation/verify/verify.go),
# echoing back the digest it was handed. So "the output names the digest" is satisfied on
# every invocation, including a #10418-shaped one, and an implementation that checked it
# would be checking nothing while appearing to check the central thing. gh's prose is
# also UI text rather than a contract, and is free to be reworded.
#
# The JSON document is the contract: an empty result array cannot be produced by a
# verification that succeeded, and the subject digest in it is the artifact gh actually
# resolved rather than the string it was passed. If that document cannot be parsed at the
# documented path, this fails closed and says so -- a schema change must block a release
# loudly, not degrade the check silently.
#
# scripts/attestation-selftest.sh drives every one of these branches against a stubbed
# gh whose output is a faithful reproduction of the real thing, `Loaded digest` line
# included, so a regression to a text assertion fails there rather than in a release.
#
# A script rather than an inline step so the release path, the self-test and the command
# in docs/supply-chain.md are provably the same check. Same reasoning as
# scripts/vuln-gate.sh: three copies would drift, and a documented command that has
# drifted from the enforced one tells a consumer nothing about the enforced one.
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
