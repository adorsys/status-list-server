#!/usr/bin/env bash
# Require a release candidate's variant tag to still resolve to the digest its run scanned.
# A final release promotes that digest; if the tag moved since, it is unclear which image
# was validated, so neither is promoted.
# Usage: verify-rc-digest.sh <image-base> <rc-tag> <variant> <digest>
set -euo pipefail

usage="usage: verify-rc-digest.sh <image-base> <rc-tag> <variant> <digest>"
image_base=${1:?$usage}
rc_tag=${2:?$usage}
variant=${3:?$usage}
digest=${4:?$usage}

fail() {
    printf '%s\n' "$@" >&2
    exit 1
}

[[ "$image_base" =~ ^[^[:space:]@:]+(:[0-9]+)?/[^[:space:]@:]+$ ]] ||
    fail "::error::'${image_base}' is not an image name without a tag or digest."
[[ "$rc_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.(0|[1-9][0-9]*)$ ]] ||
    fail "::error::'${rc_tag}' is not a release candidate tag shaped like v1.2.3-rc.1."
[[ "$variant" =~ ^[a-z0-9]+$ ]] ||
    fail "::error::'${variant}' is not an image variant suffix."
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] ||
    fail "::error::invalid release candidate digest for ${variant}: '${digest}'"

# promote-tags publishes prereleases under the version without its leading v.
rc_image="${image_base}:${rc_tag#v}-${variant}"
tagged_digest=$(docker buildx imagetools inspect "$rc_image" --format '{{ .Manifest.Digest }}')

[ "$tagged_digest" = "$digest" ] ||
    fail "::error::${rc_image} resolves to '${tagged_digest}', not ${digest}, the digest the candidate's run scanned." \
        "The candidate's tag moved after it was validated, so it is unclear which image was tested." \
        "Cut a new release candidate rather than promoting either digest."

echo "${rc_image} still resolves to ${digest}."
