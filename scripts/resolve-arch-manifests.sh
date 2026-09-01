#!/usr/bin/env bash
# Resolve a multi-platform index to exactly one child manifest per architecture.
#
# The pushed digest names an index, not an image. Scanning the index directly would
# leave the choice of platform to Trivy's default -- one architecture, silently.
#
# Scanning one architecture and inferring the other is not sound either, though it
# looks it. The images share a lockfile and the runtime stage is `FROM scratch` with
# no OS packages, but they are built by different builder images to different Rust
# targets, and `cargo auditable` records the graph cargo resolved for that target,
# not the lockfile's union across targets. An advisory reaching only one platform
# would never cross the gate.
#
# This is a script rather than an inline step so the release scan and the scheduled
# re-scan resolve manifests by the same rule. Same reasoning as scripts/vuln-gate.sh:
# two copies would drift, and the drift would be undetectable -- a re-scan resolving
# different manifests than the release scan tells you nothing about the release scan.
#
# Prints one `<arch> <manifest-digest>` line per requested architecture on stdout;
# progress goes to stderr so callers can consume the output. Exit status is 0 only
# when every requested architecture resolved to exactly one manifest.
#
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

# No silent no-op form: called with no architectures this would resolve nothing and
# exit clean, which reads exactly like a successful resolution of everything.
[ "$#" -gt 0 ] || {
    echo "::error::no architectures requested; $0 would resolve nothing and still succeed." >&2
    exit 1
}

index=$(docker buildx imagetools inspect --raw "$image_ref")

for arch in "$@"; do
    # env.SCAN_ARCH rather than a --arg variable: `$arch` in a single-quoted jq
    # program reads as an unexpanded shell variable.
    matches=$(printf '%s' "$index" | SCAN_ARCH="$arch" jq -c '[.manifests[]
      | select(.platform.os == "linux" and .platform.architecture == env.SCAN_ARCH)
      | .digest]')

    count=$(printf '%s' "$matches" | jq 'length')
    if [ "$count" -ne 1 ]; then
        echo "::error::expected exactly one linux/${arch} manifest in ${image_ref}, found ${count}." >&2
        exit 1
    fi

    manifest=$(printf '%s' "$matches" | jq -r '.[0]')
    echo "resolved linux/${arch}: ${manifest}" >&2
    printf '%s %s\n' "$arch" "$manifest"
done
