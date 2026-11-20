#!/usr/bin/env bash
set -euo pipefail
export RENDER_TEMP="${RENDER_TEMP:-/tmp}"
python3 -c 'import jsonschema'

EG_VERSION=v1.9.3
crds=$(mktemp -d "${RENDER_TEMP}/envoy-gateway-crds.XXXXXX")
while read -r sha256 path; do
  curl --silent --show-error --fail --location \
    --retry 5 --retry-delay 5 --retry-all-errors \
    --output "${crds}/${path##*/}" \
    "https://raw.githubusercontent.com/envoyproxy/gateway/${EG_VERSION}/charts/gateway-helm/charts/crds/crds/${path}"
  echo "${sha256}  ${crds}/${path##*/}" | sha256sum --check --strict
done <<'EOF'
f0342ed49e7cd1b62624659984ea2934addd334efc8630827d0e1a81194b157a gatewayapi-crds.yaml
cd75a4c222df5487aa9ca8957b48bcc3255eb25de02ed9153faf620bc160f786 generated/gateway.envoyproxy.io_backendtrafficpolicies.yaml
2c7eaa1ce30de626e9c362b8d9002281c2f435f970020fa81902ad7f30b38d5b generated/gateway.envoyproxy.io_clienttrafficpolicies.yaml
360525b418bb603dcd29786c4b5b8f93d0afd9610378c3b4a9b64a459cb74fb0 generated/gateway.envoyproxy.io_envoyproxies.yaml
EOF

python3 scripts/validate-envoy-gateway-crds.py "$EG_VERSION" "$crds" "${RENDER_TEMP}/rendered" \
  deploy/helm/envoy-gateway-platform.yaml
