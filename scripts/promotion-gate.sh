#!/usr/bin/env bash
# Decide whether a pull request into stage or main may merge.
# Into main, the head must be the latest RC for its Cargo.toml version with a passing
# deploy.yml push run, and must already contain main. resolve-rc.sh applies the same rules
# after the merge, so a gate that passes here cannot leave a final tag without an image.
# Usage: promotion-gate.sh <base> <head-branch> <head-sha> <head-repository> <base-repository> <repository>
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: promotion-gate.sh <base> <head-branch> <head-sha> <head-repository> <base-repository> <repository>" >&2
  exit 2
fi

base_branch=$1
head_branch=$2
head_sha=$3
head_repository=$4
base_repository=$5
repository=$6
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

if [[ -z "$head_repository" || "$head_repository" != "$base_repository" ]]; then
  echo "::error::Promotion branches must come from the base repository $base_repository; this pull request comes from ${head_repository:-an unavailable repository}."
  exit 1
fi

if [[ "$base_branch" == "stage" ]]; then
  if [[ "$head_branch" != "develop" ]]; then
    echo "::error::Pull requests into stage must come from develop; this pull request comes from $head_branch."
    exit 1
  fi
  exit 0
fi

if [[ "$base_branch" != "main" ]]; then
  echo "::error::Unsupported promotion target: $base_branch."
  exit 1
fi

if [[ "$head_branch" != "stage" && "$head_branch" != hotfix/* ]]; then
  echo "::error::Pull requests into main must come from stage or hotfix/*; this pull request comes from $head_branch."
  exit 1
fi

if ! git -C "$repository" cat-file -e "${head_sha}^{commit}" 2>/dev/null; then
  echo "::error::Commit $head_sha is not in the fetched history; re-run this check."
  exit 1
fi

version=$(git -C "$repository" show "${head_sha}:Cargo.toml" |
  python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["package"]["version"])')
if [[ ! "$version" =~ $semver ]]; then
  echo "::error::Version '$version' in Cargo.toml is not a release semver version."
  exit 1
fi

if [[ "$head_branch" == hotfix/* ]]; then
  # Untagged is not enough: release-plz tags whatever main carries, so an older version would be released below the current one.
  latest_final=$(git -C "$repository" tag --list 'v*' \
    | sed 's/^v//' \
    | grep -E "$semver" \
    | sort -V \
    | tail -n 1 || true)
  if [[ -n "$latest_final" && "$(printf '%s\n%s\n' "$version" "$latest_final" | sort -V | tail -n 1)" == "$latest_final" ]]; then
    echo "::error::Hotfix version $version must be newer than the latest release v$latest_final; bump Cargo.toml before promoting."
    exit 1
  fi
fi

# A merge that brings in main-only commits yields a tree no candidate was built from.
if ! git -C "$repository" merge-base --is-ancestor refs/remotes/origin/main "$head_sha"; then
  echo "::error::$head_branch at $head_sha does not contain the current main; merge main into $head_branch and cut a new release candidate before promoting."
  exit 1
fi

rc_tag=$(git -C "$repository" tag --list "v${version}-rc.*" | bash "${script_dir}/select-latest-rc.sh" "$version")
# refs/tags/, not the bare name, so a branch of the same name can't shadow the tag.
rc_sha=$(git -C "$repository" rev-parse "refs/tags/${rc_tag}^{commit}")
if [[ "$head_sha" != "$rc_sha" ]]; then
  echo "::error::Promotion to main must use the latest release candidate $rc_tag at commit $rc_sha; this pull request head is $head_sha. If a candidate for the head is still being tagged or deployed, re-run this check after its Build and Deploy to EKS run passes."
  exit 1
fi

# Same query as resolve-rc.sh, so the gate and the release agree on which run validates the candidate.
run=$(gh run list -R "$base_repository" --workflow deploy.yml --event push --branch "$rc_tag" --limit 1 \
  --json databaseId,status,conclusion,headSha,url | jq -c '.[0] // empty')
if [[ -z "$run" ]]; then
  echo "::error::Promotion requires a successful Build and Deploy to EKS run for $rc_tag at commit $rc_sha; no matching run exists."
  exit 1
fi
run_status=$(printf '%s' "$run" | jq -r '.status')
run_conclusion=$(printf '%s' "$run" | jq -r '.conclusion // ""')
run_sha=$(printf '%s' "$run" | jq -r '.headSha')
run_url=$(printf '%s' "$run" | jq -r '.url')
if [[ "$run_sha" != "$rc_sha" ]]; then
  echo "::error::The latest run for $rc_tag built $run_sha, but the tag points at $rc_sha; cut a new release candidate."
  exit 1
fi
if [[ "$run_status" != "completed" || "$run_conclusion" != "success" ]]; then
  echo "::error::Promotion requires successful validation of $rc_tag at commit $rc_sha; its latest run is $run_status (${run_conclusion:-no conclusion}): $run_url. Re-run this check once that run passes."
  exit 1
fi
echo "Promotion matches validated release candidate $rc_tag at $rc_sha ($run_url)."
