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

    # The same strict form the callers validate an index digest with, applied to the
    # child manifest they never checked. This value is registry-controlled data that
    # both callers interpolate into `$GITHUB_ENV` as `SCAN_REF_<ARCH>=...`, so a
    # newline inside it -- which `jq -r` emits literally -- would inject arbitrary
    # environment variables into every later step of the job.
    #
    # Low likelihood, since the registry is our own. Checked anyway because it costs
    # three lines, and because leaving the one unvalidated path pointing at the more
    # dangerous sink is how the next person concludes this class of input is trusted.
    #
    # `[[ =~ ]]` and not `grep -Eq`: grep matches line by line, so it accepts a value
    # whose *first* line is a valid digest and whose second is `LD_PRELOAD=...` -- it
    # would wave through precisely the payload this check exists to stop. Bash matches
    # the pattern against the whole string, so `$` means end of value, not end of line.
    if [[ ! "$manifest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "::error::linux/${arch} manifest digest in ${image_ref} is not a valid sha256 digest." >&2
        echo "Got: '${manifest}'" >&2
        exit 1
    fi

    echo "resolved linux/${arch}: ${manifest}" >&2
    printf '%s %s\n' "$arch" "$manifest"
done
