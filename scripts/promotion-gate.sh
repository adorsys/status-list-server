#!/usr/bin/env bash
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

if [[ "$head_branch" == "stage" ]]; then
  latest_rc=$(git -C "$repository" tag --list 'v*-rc.*' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' \
    | sort -V \
    | tail -n 1 || true)
  if [[ -z "$latest_rc" ]]; then
    echo "::error::No release candidate tag matching v<version>-rc.<N> exists; stage cannot be promoted until an RC is deployed and validated."
    exit 1
  fi

  rc_sha=$(git -C "$repository" rev-parse "${latest_rc}^{commit}")
  if [[ "$head_sha" != "$rc_sha" ]]; then
    echo "::error::Stage promotion must use the latest validated RC $latest_rc at commit $rc_sha; this PR head is $head_sha."
    exit 1
  fi

  runs=$(gh api --paginate "repos/$base_repository/actions/workflows/deploy.yml/runs?head_sha=$rc_sha&event=push&per_page=100")
  latest_run=$(printf '%s\n' "$runs" | jq -s -r --arg sha "$rc_sha" --arg tag "$latest_rc" \
    '[.[].workflow_runs[]? | select(.head_sha == $sha and .head_branch == $tag and .event == "push")] | sort_by(.run_number) | last // empty | [.status, (.conclusion // ""), .html_url] | @tsv')
  if [[ -z "$latest_run" ]]; then
    echo "::error::Stage promotion requires a successful Build and Deploy to EKS run for $latest_rc at commit $rc_sha; no matching validation run exists."
    exit 1
  fi
  IFS=$'\t' read -r run_status run_conclusion run_url <<< "$latest_run"
  if [[ "$run_status" != "completed" || "$run_conclusion" != "success" ]]; then
    echo "::error::Stage promotion requires successful validation for $latest_rc at commit $rc_sha; the latest matching deployment run is $run_status (${run_conclusion:-no conclusion})${run_url:+: $run_url}."
    exit 1
  fi
  echo "Stage promotion matches successfully validated RC $latest_rc at $rc_sha ($run_url)."
  exit 0
fi

if [[ "$head_branch" == hotfix/* ]]; then
  cargo_content=$(gh api "repos/$base_repository/contents/Cargo.toml?ref=$head_sha" --jq .content | base64 --decode)
  version=$(printf '%s' "$cargo_content" | python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["package"]["version"])')
  release_tag="v${version}"
  if git -C "$repository" show-ref --verify --quiet "refs/tags/$release_tag"; then
    echo "::error::Hotfix version $version is already tagged as $release_tag; bump Cargo.toml to an untagged version before promoting."
    exit 1
  fi
  echo "Hotfix version $version has not been released yet."
  exit 0
fi

echo "::error::Pull requests into main must come from stage or hotfix/*; this pull request comes from $head_branch."
exit 1
