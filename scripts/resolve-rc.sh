#!/usr/bin/env bash
# Resolve the release candidate a final tag promotes and print it as key=value lines.
# A final release ships the image of the latest RC's deploy.yml run without rebuilding,
# so the run must have passed on the candidate's commit, and that commit must hold the
# same tree as the final one, or the release would ship an image built from other code.
# Never falls back to an older RC. Errors go to stderr; stdout is meant for $GITHUB_OUTPUT.
# Usage: resolve-rc.sh <owner/repo> <final-tag> <final-commit-sha>
set -euo pipefail

usage="usage: resolve-rc.sh <owner/repo> <final-tag> <final-commit-sha>"
repo=${1:?$usage}
final_tag=${2:?$usage}
final_sha=${3:?$usage}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

fail() {
    printf '%s\n' "$@" >&2
    exit 1
}

[[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] ||
    fail "::error::'${repo}' is not an <owner>/<repo> value."
[[ "$final_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    fail "::error::'${final_tag}' is not a final release tag shaped like v1.2.3."
[[ "$final_sha" =~ ^[a-f0-9]{40}$ ]] ||
    fail "::error::'${final_sha}' is not a full commit SHA."
version=${final_tag#v}

tags=$(gh api --paginate "repos/${repo}/git/matching-refs/tags/v${version}-rc." |
    jq -r '.[].ref | ltrimstr("refs/tags/")')
rc_tag=$(printf '%s\n' "$tags" | bash "${script_dir}/select-latest-rc.sh" "$version")

# refs/tags/, not the bare name, so a branch of the same name can't shadow the tag.
# The commits endpoint dereferences annotated tags to the commit the run built.
rc_commit=$(gh api "repos/${repo}/commits/refs/tags/${rc_tag}")
rc_sha=$(printf '%s' "$rc_commit" | jq -r '.sha // ""')
rc_tree=$(printf '%s' "$rc_commit" | jq -r '.commit.tree.sha // ""')
[[ "$rc_sha" =~ ^[a-f0-9]{40}$ && "$rc_tree" =~ ^[a-f0-9]{40}$ ]] ||
    fail "::error::${rc_tag} did not resolve to a commit and tree: '${rc_sha}' '${rc_tree}'"

final_tree=$(gh api "repos/${repo}/commits/${final_sha}" | jq -r '.commit.tree.sha // ""')
[[ "$final_tree" =~ ^[a-f0-9]{40}$ ]] ||
    fail "::error::${final_tag} commit ${final_sha} did not resolve to a tree: '${final_tree}'"

# Trees, not commits: promoting stage to main creates a new commit with the same content.
if [ "$rc_tree" != "$final_tree" ]; then
    fail "::error::${final_tag} (${final_sha}) does not contain the same files as ${rc_tag} (${rc_sha})." \
        "The candidate's image was built from different code than the release, so promoting it would" \
        "ship a version nobody validated. Tag the commit being released as the next v${version}-rc.<N>," \
        "let its run pass, then re-run this workflow."
fi

run=$(gh run list -R "$repo" --workflow deploy.yml --event push --branch "$rc_tag" --limit 1 \
    --json databaseId,status,conclusion,headSha | jq -c '.[0] // empty')
[ -n "$run" ] ||
    fail "::error::no release run of deploy.yml exists for ${rc_tag}." \
        "Its image was never built, scanned and verified, so ${final_tag} has nothing to promote."

run_id=$(printf '%s' "$run" | jq -r '.databaseId')
status=$(printf '%s' "$run" | jq -r '.status')
conclusion=$(printf '%s' "$run" | jq -r '.conclusion')
head_sha=$(printf '%s' "$run" | jq -r '.headSha')

[[ "$run_id" =~ ^[0-9]+$ ]] ||
    fail "::error::run id for ${rc_tag} is not numeric: '${run_id}'"
[ "$status" = "completed" ] ||
    fail "::error::run ${run_id} for ${rc_tag} has not finished (status '${status}')." \
        "Wait for it to pass, then re-run this workflow."
[ "$conclusion" = "success" ] ||
    fail "::error::the latest release candidate ${rc_tag} was not validated: run ${run_id} concluded '${conclusion}'." \
        "A final release never rebuilds and never falls back to an older candidate." \
        "Fix the cause, cut the next v${version}-rc.<N>, and let its run pass before re-running ${final_tag}."
[ "$head_sha" = "$rc_sha" ] ||
    fail "::error::run ${run_id} built ${head_sha}, but ${rc_tag} now points at ${rc_sha}." \
        "The tag moved after it was validated, so that run's image is not the candidate's."

echo "Promoting the image validated by ${rc_tag} (run ${run_id}, commit ${rc_sha}) as ${final_tag}." >&2
printf '%s\n' \
    "rc_tag=${rc_tag}" \
    "rc_ref=refs/tags/${rc_tag}" \
    "rc_run_id=${run_id}" \
    "rc_sha=${rc_sha}"
