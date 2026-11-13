#!/usr/bin/env bash
# Resolve the published fscert image and verify its release provenance.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <stable-tag> <image-base> <owner/repo>" >&2
  exit 2
fi

tag=$1
image=$2
repo=$3
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "::error::Previous release tag is not a stable version." >&2
  exit 1
}
[[ "$image" =~ ^ghcr\.io/[A-Za-z0-9._-]+/status-list-server$ ]] || {
  echo "::error::Invalid image base." >&2
  exit 1
}

digest=$(docker buildx imagetools inspect "${image}:${tag#v}-fscert" --format '{{ .Manifest.Digest }}')
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  echo "::error::Previous release image digest is missing or malformed." >&2
  exit 1
}

if [[ "$tag" == v1.2.0 ]]; then
  # This release predates Sigstore signing; fail if its mutable tag ever moves.
  [[ "$digest" == sha256:8e7ae2618c6509c671e5b59a7d557655d35811f8f30e085485fdb1194944813a ]] || {
    echo "::error::The v1.2.0-fscert tag no longer points to its published digest." >&2
    exit 1
  }
else
  final_sha=$(gh api "repos/${repo}/commits/refs/tags/${tag}" --jq .sha)
  [[ "$final_sha" =~ ^[a-f0-9]{40}$ ]] || {
    echo "::error::Previous release tag did not resolve to a commit." >&2
    exit 1
  }
  rc_ref=$(bash "${script_dir}/resolve-rc.sh" "$repo" "$tag" "$final_sha" | sed -n 's/^rc_ref=//p')
  [[ "$rc_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]] || {
    echo "::error::Previous release did not resolve to a validated RC ref." >&2
    exit 1
  }
  bash "${script_dir}/verify-attestation.sh" "${image}@${digest}" "$repo" "$rc_ref" >&2
fi

printf '%s\n' "$digest"
