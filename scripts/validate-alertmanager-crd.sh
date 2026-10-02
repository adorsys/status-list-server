#!/usr/bin/env bash
set -euo pipefail
export RENDER_TEMP="${RENDER_TEMP:-/tmp}"
set -euo pipefail
python3 -c 'import jsonschema'

crd=${RENDER_TEMP}/crd-alertmanagerconfigs-91.4.0.yaml
curl -fsSL -o "$crd" \
  "https://raw.githubusercontent.com/prometheus-community/helm-charts/kube-prometheus-stack-91.4.0/charts/kube-prometheus-stack/charts/crds/crds/crd-alertmanagerconfigs.yaml"

python3 - <<'PY'
import os, sys, yaml
from pathlib import Path
from jsonschema import Draft7Validator

# The pinned CRD uses the OpenAPI "=" scalar (e.g. enum: ["=", "!=", ...])
# which yaml.safe_load rejects; map the value tag to a scalar/mapping safely.
def _value_constructor(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    return loader.construct_mapping(node, deep=True)

class Loader(yaml.SafeLoader):
    pass
Loader.add_constructor('tag:yaml.org,2002:value', _value_constructor)

crd = yaml.load(open(str(Path(os.environ['RENDER_TEMP']) / 'crd-alertmanagerconfigs-91.4.0.yaml')), Loader=Loader)
versions = crd['spec']['versions']
served = [v['name'] for v in versions]
print("pinned 91.4.0 AlertmanagerConfig CRD served versions:", served)

path = str(Path(os.environ['RENDER_TEMP']) / 'rendered/alerting-slack/status-list-server/templates/alertmanagerconfig.yaml')
docs = [d for d in yaml.safe_load_all(open(path)) if d]
amc = next((d for d in docs if d.get('kind') == 'AlertmanagerConfig'), None)
if amc is None:
    sys.exit("ERROR: no AlertmanagerConfig rendered for the enabled alerting route")

api = amc['apiVersion']
group, _, version = api.partition('/')
if version not in served:
    sys.exit(f"ERROR: rendered AlertmanagerConfig uses {api}, but the pinned "
             f"kube-prometheus-stack 91.4.0 CRD serves only {served}")

schema = next(v for v in versions if v['name'] == version)['schema']['openAPIV3Schema']
# The CRD schema is a full-object schema (required: ['spec', 'metadata', ...]).
# Validate the rendered spec against the spec sub-schema, not the object schema.
spec_schema = schema['properties']['spec']
errors = sorted(Draft7Validator(spec_schema).iter_errors(amc['spec']),
                key=lambda e: list(e.path))
if errors:
    for e in errors:
        print("INVALID:", list(e.path), "->", e.message)
    sys.exit(f"ERROR: rendered AlertmanagerConfig fails validation against the "
             f"pinned 91.4.0 {api} CRD schema")
print("rendered AlertmanagerConfig validates against the pinned 91.4.0 CRD schema")
PY
