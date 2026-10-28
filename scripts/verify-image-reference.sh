#!/usr/bin/env bash
# Check the chart prefers the scanned digest over any tag, which deploy.yml relies on.
# Needs helm and Python 3 with PyYAML. Run from the repo root.
set -euo pipefail

# Adds test-only audience and issuer-registry values: the chart has no defaults, so deployments must choose their own.
helm() {
  local action="$1"
  shift
  if [[ "$action" == template || "$action" == lint ]]; then
    command helm "$action" --set-string statuslist.env.APP_MANAGEMENT_AUTH__AUDIENCES=https://helm-ci.invalid/api/v1 --set statuslist.issuerRegistry.volume.configMap.name=helm-ci-issuers "$@"
  else
    command helm "$action" "$@"
  fi
}

for tool in helm python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "::error::$tool is required by $0 but was not found on PATH."
        exit 1
    }
done

[ -f deploy/helm/chart/Chart.yaml ] || {
    echo "::error::deploy/helm/chart/Chart.yaml not found. Run $0 from the repository root."
    exit 1
}

repo="ghcr.io/adorsys/status-list-server"
digest="sha256:$(printf 'a%.0s' $(seq 1 64))"
app_version=$(helm show chart deploy/helm/chart | sed -nE 's/^appVersion:[[:space:]]*"?([^"]+)"?[[:space:]]*$/\1/p')
echo "chart appVersion: ${app_version}"

# Pick the container by name so an initContainer can't be matched instead.
render() {
    helm template status-list-server deploy/helm/chart -s templates/deployment.yaml "$@" \
        | python3 -c '
import sys, yaml
for document in yaml.safe_load_all(sys.stdin):
    for container in document["spec"]["template"]["spec"]["containers"]:
        if container["name"] == "status-list-server":
            print(container["image"] + "|" + container["imagePullPolicy"] + "|", end="")
'

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

expect_failure() {
    want="$1"; shift
    stderr=$(mktemp)
    if helm template status-list-server deploy/helm/chart -s templates/deployment.yaml "$@" >/dev/null 2>"${stderr}"; then
        echo "::error::chart accepted invalid image configuration for: $*"
        rm -f "${stderr}"
        exit 1
    fi
    if ! grep -q "${want}" "${stderr}"; then
        echo "::error::chart failed with an unexpected message for: $*"
        echo "  expected stderr to contain: ${want}"
        echo "  actual stderr:"
        sed 's/^/    /' "${stderr}"
        rm -f "${stderr}"
        exit 1
    fi
    rm -f "${stderr}"
    echo "ok: rejected $* -> ${want}"
}

# The first version line in Cargo.toml is the package's; later ones are deps.
crate_version=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/^version = "([^"]+)".*/\1/')
default_tag="${crate_version}-fscert"
if [ "${app_version}" != "${default_tag}" ]; then
    echo "::error::Chart appVersion (${app_version}) does not match the provider-neutral default image tag (${default_tag}). Base installs would point at the wrong image variant."
    exit 1
fi
echo "appVersion matches provider-neutral default image tag: ${default_tag}"

# A digest is content-addressed, so IfNotPresent; a tag is mutable, so Always.
expect "${repo}@${digest}|IfNotPresent|" \
    --set-string statuslist.image.digest="${digest}"
expect "${repo}:test-tag|Always|" \
    --set-string statuslist.image.tag=test-tag
expect "${repo}@${digest}|IfNotPresent|" \
    --set-string statuslist.image.tag=test-tag \
    --set-string statuslist.image.digest="${digest}"
expect "${repo}:${app_version}|Always|"
expect "${repo}:${crate_version}-aws|Always|" \
    --set-string statuslist.image.variant=aws
expect "${repo}@${digest}|Always|" \
    --set-string statuslist.image.digest="${digest}" \
    --set-string statuslist.image.pullPolicy=Always
# --set x=null must clear the digest, not render repo@<nil>.
expect "${repo}:test-tag|Always|" \
    --set-string statuslist.image.tag=test-tag \
    --set statuslist.image.digest=null

expect_failure "sha256:\\[a-f0-9\\]{64}" \
    --set-string statuslist.image.digest=not-a-digest

expect_failure "statuslist.image.tag or statuslist.image.digest" \
    --set postgres.enabled=false \
    --set-string statuslist.env.APP_DATABASE__BACKEND=mysql \
    --set-string statuslist.env.APP_DATABASE__HOST=mysql.example.internal
