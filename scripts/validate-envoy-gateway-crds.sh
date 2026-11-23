#!/usr/bin/env bash
set -euo pipefail
export RENDER_TEMP="${RENDER_TEMP:-/tmp}"
python3 -c 'import jsonschema'

EG_VERSION=v1.10.0
crds=$(mktemp -d "${RENDER_TEMP}/envoy-gateway-crds.XXXXXX")
while read -r sha256 path; do
  curl --silent --show-error --fail --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    --output "${crds}/${path##*/}" \
    "https://raw.githubusercontent.com/envoyproxy/gateway/${EG_VERSION}/charts/gateway-helm/charts/crds/crds/${path}"
  echo "${sha256}  ${crds}/${path##*/}" | sha256sum --check --strict
done <<'EOF'
f0342ed49e7cd1b62624659984ea2934addd334efc8630827d0e1a81194b157a gatewayapi-crds.yaml
d6f3aec0844dd3d88e6a28a8a94f57941bef2e56566d806295260fe2b1c1a789 generated/gateway.envoyproxy.io_backendtrafficpolicies.yaml
a990b7cd9f2d3aaa9f47a5d3f09083bd338b089562f9a293365fa97016faaad0 generated/gateway.envoyproxy.io_clienttrafficpolicies.yaml
b3b9f2b9449caa418f137c0ad2ddfacf9b6c16964ef0313f0ee013adf6ec5444 generated/gateway.envoyproxy.io_envoyproxies.yaml
EOF

python3 scripts/validate-envoy-gateway-crds.py "$EG_VERSION" "$crds" "${RENDER_TEMP}/rendered" \
  deploy/helm/envoy-gateway-platform.yaml
