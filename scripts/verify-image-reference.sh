#!/usr/bin/env bash
# Verify that the chart resolves image references the way the deploy path depends on.
#
# The `image` / `imagePullPolicy` conditionals in `helm/chart/templates/deployment.yaml`
# are what make "production runs the artifact CI scanned" true: `deploy.yml` passes the
# scanned digest as `statuslist.image.digest`, and the chart must prefer it over any tag.
# Every other Helm render in CI uses default values, so without this only the tag branch
# would ever be exercised -- the digest branch would ship untested.
#
# This is a script rather than an inline workflow step so it can be run locally against a
# working tree before pushing, and so the workflow reads as one named check rather than
# seventy lines of shell. Same reasoning as scripts/vuln-gate.sh.
#
# Requires `helm` and `yq`. Run from the repository root; takes no arguments.
# Exit status is 0 when every expectation holds, 1 when any does not.
set -euo pipefail

for tool in helm yq; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "::error::$tool is required by $0 but was not found on PATH."
        exit 1
    }
done

[ -f helm/chart/Chart.yaml ] || {
    echo "::error::helm/chart/Chart.yaml not found. Run $0 from the repository root."
    exit 1
}

repo="ghcr.io/adorsys/status-list-server"
digest="sha256:$(printf 'a%.0s' $(seq 1 64))"
app_version=$(helm show chart helm/chart | sed -nE 's/^appVersion:[[:space:]]*"?([^"]+)"?[[:space:]]*$/\1/p')
echo "chart appVersion: ${app_version}"

# Selected by container name rather than by whether the image happens to be
# quoted, so adding or quoting an initContainer cannot silently retarget it.
# `tr` strips any quoting yq adds and the CR from a CRLF checkout.
render() {
    helm template status-list-server helm/chart -s templates/deployment.yaml "$@" \
        | yq '.spec.template.spec.containers[]
              | select(.name == "status-list-server")
              | (.image, .imagePullPolicy)' \
        | tr -d '"\r' \
        | tr '\n' '|'
}

expect() {
    want="$1"; shift
    got=$(render "$@")
    if [ "${got}" != "${want}" ]; then
        echo "::error::helm rendered the wrong image reference for: $*"
        echo "  expected: ${want}"
        echo "  actual:   ${got}"
        exit 1
    fi
    echo "ok: $* -> ${want}"
}

# appVersion is the default image tag when neither tag nor digest is set. Release tags
# are variant-suffixed, so the base chart must resolve to the provider-neutral
# filesystem-certificate variant. AWS production selects -aws explicitly.
# First `version = ` line is [package]; later ones are deps.
crate_version=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/^version = "([^"]+)".*/\1/')
default_tag="${crate_version}-fscert"
if [ "${app_version}" != "${default_tag}" ]; then
    echo "::error::Chart appVersion (${app_version}) does not match the provider-neutral default image tag (${default_tag}). appVersion is the chart's default image tag, so this points base installs at the wrong image."
    exit 1
fi
echo "appVersion matches provider-neutral default image tag: ${default_tag}"

# A digest is content-addressed, so IfNotPresent; a tag is mutable, so Always.
expect "${repo}@${digest}|IfNotPresent|" \
    --set-string statuslist.image.digest="${digest}"
expect "${repo}:test-tag|Always|" \
    --set-string statuslist.image.tag=test-tag
# Digest wins over a tag supplied alongside it, which is what deploy.yml does.
expect "${repo}@${digest}|IfNotPresent|" \
    --set-string statuslist.image.tag=test-tag \
    --set-string statuslist.image.digest="${digest}"
# No tag and no digest falls back to the published appVersion, never to "latest".
expect "${repo}:${app_version}|Always|"
# An explicit pullPolicy still overrides the derived one.
expect "${repo}@${digest}|Always|" \
    --set-string statuslist.image.digest="${digest}" \
    --set-string statuslist.image.pullPolicy=Always
# `--set x=null` is the documented way to clear a value; it must fall back to the tag,
# not render `repo@<nil>`.
expect "${repo}:test-tag|Always|" \
    --set-string statuslist.image.tag=test-tag \
    --set statuslist.image.digest=null

# A malformed digest must fail at template time, not 10 minutes later as an
# ImagePullBackOff under `helm upgrade --atomic --wait`.
if helm template status-list-server helm/chart -s templates/deployment.yaml \
    --set-string statuslist.image.digest=not-a-digest > /dev/null 2>&1; then
    echo "::error::chart accepted a malformed image digest instead of failing."
    exit 1
fi
echo "ok: malformed digest rejected at template time"
