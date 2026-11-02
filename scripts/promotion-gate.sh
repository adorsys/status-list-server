#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: promotion-gate.sh <base> <head-branch> <head-sha> <repository>" >&2
  exit 2
fi

base_branch=$1
head_branch=$2
head_sha=$3
repository=$4

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
  echo "Stage promotion matches latest RC $latest_rc at $rc_sha."
  exit 0
fi

if [[ "$head_branch" == hotfix/* ]]; then
  version=$(python3 -c 'import pathlib, sys, tomllib; print(tomllib.loads((pathlib.Path(sys.argv[1]) / "Cargo.toml").read_text())["package"]["version"])' "$repository")
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
