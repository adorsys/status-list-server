#!/usr/bin/env bash
# Print one "<arch> <manifest-digest>" line per requested arch of a multi-platform index.
# Each arch is scanned on its own: cargo auditable records per-target graphs.
# Usage: resolve-arch-manifests.sh <image-ref> <arch>...
set -euo pipefail

for tool in docker jq; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "::error::$tool is required by $0 but was not found on PATH." >&2
        exit 1
    }
done

image_ref=${1:?usage: resolve-arch-manifests.sh <image-ref> <arch>...}
shift

[ "$#" -gt 0 ] || {
    echo "::error::no architectures requested; $0 would resolve nothing and still succeed." >&2
    exit 1
}

index=$(docker buildx imagetools inspect --raw "$image_ref")

for arch in "$@"; do
    # env.SCAN_ARCH, not --arg: $arch in single quotes looks like an unexpanded shell variable.
    matches=$(printf '%s' "$index" | SCAN_ARCH="$arch" jq -c '[.manifests[]
      | select(.platform.os == "linux" and .platform.architecture == env.SCAN_ARCH)
      | .digest]')

    count=$(printf '%s' "$matches" | jq 'length')
    if [ "$count" -ne 1 ]; then
        echo "::error::expected exactly one linux/${arch} manifest in ${image_ref}, found ${count}." >&2
        exit 1
    fi

    manifest=$(printf '%s' "$matches" | jq -r '.[0]')

    # Registry data that callers write into $GITHUB_ENV: a newline would inject env vars into later steps.
    # [[ =~ ]], not grep, which matches per line.
    if [[ ! "$manifest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "::error::linux/${arch} manifest digest in ${image_ref} is not a valid sha256 digest." >&2
        echo "Got: '${manifest}'" >&2
        exit 1
    fi

    echo "resolved linux/${arch}: ${manifest}" >&2
    printf '%s %s\n' "$arch" "$manifest"
done
