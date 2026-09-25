#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_ENDPOINT="${API_ENDPOINT:-http://localhost:8000}"
API_NAME_VERSION="${API_NAME_VERSION:-Status List Server:0.1.0}"
OPENAPI_ARTIFACT="${OPENAPI_ARTIFACT:-docs/openapi.yaml}"
POSTMAN_ARTIFACT="${POSTMAN_ARTIFACT:-postman/status-list-server.postman_collection.json}"
MICROCKS_IMAGE="${MICROCKS_IMAGE:-quay.io/microcks/microcks-cli:nightly}"
MICROCKS_COMMAND="${MICROCKS_COMMAND:-microcks}"
MICROCKS_WAIT_FOR="${MICROCKS_WAIT_FOR:-30sec}"
MICROCKS_READY_TIMEOUT="${MICROCKS_READY_TIMEOUT:-180s}"
MICROCKS_UBER_IMAGE="${MICROCKS_UBER_IMAGE:-quay.io/microcks/microcks-uber:latest-native}"
MICROCKS_MANAGED_PORT="${MICROCKS_MANAGED_PORT:-8585}"
RUN_POSTMAN_CONFORMANCE="${RUN_POSTMAN_CONFORMANCE:-false}"
MICROCKS_VERBOSE="${MICROCKS_VERBOSE:-true}"
MICROCKS_MANAGED_CONTAINER=""
token_data_file=""
microcks_openapi_artifact=""
microcks_postman_artifact=""

cleanup() {
  if [[ -n "${MICROCKS_MANAGED_CONTAINER:-}" ]]; then
    docker rm -f "$MICROCKS_MANAGED_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [[ -n "${token_data_file:-}" ]]; then
    rm -f "$token_data_file"
  fi
  if [[ -n "${microcks_openapi_artifact:-}" ]]; then
    rm -f "$microcks_openapi_artifact"
  fi
  if [[ -n "${microcks_postman_artifact:-}" ]]; then
    rm -f "$microcks_postman_artifact"
  fi
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

generate_token_data() {
  local output_file="$1"
  node - "$output_file" <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

const outputFile = process.argv[2];
const now = Math.floor(Date.now() / 1000);
const issuerId = `microcks-issuer-${Date.now()}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

const header = { alg: 'ES256', typ: 'JWT', kid: issuerId };
const payload = { iss: issuerId, iat: now, exp: now + 3600 };
const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
const signature = crypto.sign('sha256', Buffer.from(signingInput), {
  key: privateKey,
  dsaEncoding: 'ieee-p1363'
});

const data = {
  issuerId,
  secondaryIssuerId: `${issuerId}-secondary`,
  listId: crypto.randomUUID(),
  publicKeyJwk: crypto.createPublicKey(publicKey).export({ format: 'jwk' }),
  token: `${signingInput}.${base64url(signature)}`
};

fs.writeFileSync(outputFile, JSON.stringify(data, null, 2), { mode: 0o600 });
NODE
}

json_field() {
  local file="$1"
  local field="$2"
  node -e "const fs = require('fs'); const data = JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); console.log(data[process.argv[2]]);" "$file" "$field"
}

build_operations_headers() {
  node -e "process.stdout.write(JSON.stringify({
    globals: [
      { name: 'Authorization', values: 'Bearer ' + process.argv[1] }
    ],
    'POST /api/v1/credentials': [
      { name: 'Accept', values: 'application/json' },
      { name: 'Content-Type', values: 'application/json' }
    ],
    'PUT /api/v1/status-lists/{list_id}/statuses': [
      { name: 'Accept', values: 'application/json' },
      { name: 'Content-Type', values: 'application/json' }
    ],
    'PATCH /api/v1/status-lists/{list_id}/statuses': [
      { name: 'Accept', values: 'application/json' },
      { name: 'Content-Type', values: 'application/json' }
    ],
    'GET /api/v1/aggregation': [
      { name: 'Accept', values: 'application/json' }
    ],
    'GET /metrics': [
      { name: 'Accept', values: 'text/plain' }
    ],
    'GET /api/v1/status-lists/{list_id}': [
      { name: 'Accept', values: 'application/statuslist+jwt' },
      { name: 'Accept-Encoding', values: 'identity' }
    ]
  }));" "$STATUS_LIST_AUTH_TOKEN"
}

prepare_microcks_openapi_artifact() {
  local output_file
  output_file="$(mktemp "$ROOT_DIR/.microcks-openapi.XXXXXX.yaml")"
  python3 - "$OPENAPI_ARTIFACT" "$output_file" "$token_data_file" <<'PY'
import sys
from pathlib import Path
import json

import yaml

source = Path(sys.argv[1])
target = Path(sys.argv[2])
token_data = json.loads(Path(sys.argv[3]).read_text())
doc = yaml.safe_load(source.read_text())

# Microcks treats component-level named response examples as concrete test
# cases. This API's reusable error examples document possible failures, but
# they are not paired with request examples that intentionally trigger those
# failures, so they make the schema runner send generic requests while expecting
# 4xx responses. Keep the published OpenAPI spec rich, but feed Microcks a
# conformance-focused copy containing only examples it can execute reliably.
for response in doc.get("components", {}).get("responses", {}).values():
    for media in response.get("content", {}).values():
        media.pop("examples", None)

paths = doc["paths"]
list_id = token_data["listId"]
public_key = token_data["publicKeyJwk"]
secondary_issuer = token_data["secondaryIssuerId"]

def keep_responses(operation, *statuses):
    responses = operation.get("responses", {})
    operation["responses"] = {status: responses[status] for status in statuses if status in responses}

def text_example(operation, status, name, value):
    content = operation["responses"][status]["content"]["text/plain"]
    content["examples"] = {name: {"value": value}}

def json_example(operation, status, name, value):
    content = operation["responses"][status]["content"]["application/json"]
    content["examples"] = {name: {"value": value}}

def ref_response(operation, status, name):
    operation["responses"][status]["x-microcks-refs"] = [name]

welcome = paths["/"]["get"]
keep_responses(welcome, "200")
text_example(welcome, "200", "welcome", "Status list Server")

live = paths["/health/live"]["get"]
keep_responses(live, "200")
text_example(live, "200", "live", "OK")

legacy_live = paths["/health"]["get"]
keep_responses(legacy_live, "200")
text_example(legacy_live, "200", "legacyLive", "OK")

ready = paths["/health/ready"]["get"]
keep_responses(ready, "200")
text_example(ready, "200", "ready", "READY")

# Metrics may be enabled or disabled by runtime configuration. The Postman
# collection asserts both accepted outcomes; omit it from the generated
# OpenAPI schema-runner copy so local config does not make conformance flaky.
paths.pop("/metrics", None)

credentials = paths["/api/v1/credentials"]["post"]
keep_responses(credentials, "202")
credentials["requestBody"]["content"]["application/json"]["examples"] = {
    "registerSecondaryIssuer": {
        "value": {
            "issuer": secondary_issuer,
            "public_key": public_key,
        }
    }
}
json_example(credentials, "202", "registerSecondaryIssuer", {
    "status": "Credentials stored successfully",
})

aggregation = paths["/api/v1/aggregation"]["get"]
keep_responses(aggregation, "200")
json_example(aggregation, "200", "aggregation", {"status_lists": []})

status_path = paths["/api/v1/status-lists/{list_id}/statuses"]
status_path["parameters"][0]["examples"] = {
    "publishStatusList": {"value": list_id},
    "updateStatusList": {"value": list_id},
}

publish = status_path["put"]
keep_responses(publish, "201")
publish["requestBody"]["content"]["application/json"]["examples"] = {
    "publishStatusList": {
        "value": {
            "statuses": [
                {"index": 0, "status": 0},
                {"index": 1, "status": 1},
                {"index": 2, "status": 2},
            ]
        }
    }
}
ref_response(publish, "201", "publishStatusList")

update = status_path["patch"]
keep_responses(update, "200")
update["requestBody"]["content"]["application/json"]["examples"] = {
    "updateStatusList": {
        "value": {
            "statuses": [
                {"index": 1, "status": 1},
            ]
        }
    }
}
ref_response(update, "200", "updateStatusList")

get_status = paths["/api/v1/status-lists/{list_id}"]["get"]
keep_responses(get_status, "200")
for parameter in get_status["parameters"]:
    if parameter["name"] == "list_id":
        parameter["examples"] = {"statusListJwt": {"value": list_id}}
    elif parameter["name"] == "Accept":
        parameter["examples"] = {"statusListJwt": {"value": "application/statuslist+jwt"}}
    elif parameter["name"] == "Accept-Encoding":
        parameter["examples"] = {"statusListJwt": {"value": "identity"}}
get_status["responses"]["200"]["content"]["application/statuslist+jwt"]["examples"] = {
    "statusListJwt": {"value": "eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6e319.signature"}
}

target.write_text(yaml.safe_dump(doc, sort_keys=False))
PY
  microcks_openapi_artifact="$output_file"
  printf '%s\n' "$microcks_openapi_artifact"
}

prepare_microcks_postman_artifact() {
  local output_file
  output_file="$(mktemp "$ROOT_DIR/.microcks-postman.XXXXXX.json")"
  node - "$POSTMAN_ARTIFACT" "$output_file" "$token_data_file" "$(endpoint_for_container "$API_ENDPOINT")" "$STATUS_LIST_AUTH_TOKEN" <<'NODE'
const fs = require('fs');

const [sourceFile, targetFile, tokenDataFile, baseUrl, authToken] = process.argv.slice(2);
const collection = JSON.parse(fs.readFileSync(sourceFile, 'utf8'));
const tokenData = JSON.parse(fs.readFileSync(tokenDataFile, 'utf8'));

const replacements = new Map([
  ['{{baseUrl}}', baseUrl],
  ['{{list_id}}', tokenData.listId],
  ['{{issuer_id}}', tokenData.issuerId],
  ['{{token}}', authToken],
  ['{{historical_time}}', Math.floor(Date.now() / 1000).toString()],
]);

function replaceStrings(value) {
  if (typeof value === 'string') {
    let replaced = value;
    for (const [needle, replacement] of replacements) {
      replaced = replaced.split(needle).join(replacement);
    }
    return replaced;
  }
  if (Array.isArray(value)) {
    return value.map(replaceStrings);
  }
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      value[key] = replaceStrings(value[key]);
    }
  }
  return value;
}

replaceStrings(collection);

function visitItems(items, visitor) {
  for (const item of items || []) {
    visitor(item);
    if (item.item) {
      visitItems(item.item, visitor);
    }
  }
}

visitItems(collection.item, (item) => {
  if (item.name === 'Register issuer credentials' && item.request?.body?.raw) {
    item.request.body.raw = JSON.stringify({
      issuer: tokenData.issuerId,
      public_key: tokenData.publicKeyJwk,
    }, null, 2);
  }
});

for (const variable of collection.variable || []) {
  if (variable.key === 'baseUrl') variable.value = baseUrl;
  if (variable.key === 'list_id') variable.value = tokenData.listId;
  if (variable.key === 'issuer_id') variable.value = tokenData.issuerId;
  if (variable.key === 'token') variable.value = authToken;
  if (variable.key === 'historical_time') variable.value = Math.floor(Date.now() / 1000).toString();
}

fs.writeFileSync(targetFile, JSON.stringify(collection, null, 2));
NODE
  microcks_postman_artifact="$output_file"
  printf '%s\n' "$microcks_postman_artifact"
}

register_generated_issuer() {
  local token_file="$1"
  local body_file
  local response_file
  local status_code

  body_file="$(mktemp)"
  response_file="$(mktemp)"
  node -e "const fs = require('fs'); const data = JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); process.stdout.write(JSON.stringify({ issuer: data.issuerId, public_key: data.publicKeyJwk }));" "$token_file" > "$body_file"

  status_code="$(curl -sS -o "$response_file" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data @"$body_file" \
    "$API_ENDPOINT/api/v1/credentials")"

  rm -f "$body_file" "$response_file"

  if [[ "$status_code" != "202" && "$status_code" != "409" ]]; then
    echo "Issuer registration failed with HTTP $status_code at $API_ENDPOINT/api/v1/credentials" >&2
    exit 1
  fi
}

duration_seconds() {
  local value="$1"
  case "$value" in
    *milli) echo 1 ;;
    *sec) echo "${value%milli}" | sed 's/sec$//' ;;
    *min) echo $(( ${value%min} * 60 )) ;;
    *s) echo "${value%s}" ;;
    *m) echo $(( ${value%m} * 60 )) ;;
    *) echo "$value" ;;
  esac
}

endpoint_for_container() {
  local endpoint="$1"
  endpoint="${endpoint/http:\/\/localhost/http:\/\/host.docker.internal}"
  endpoint="${endpoint/http:\/\/127.0.0.1/http:\/\/host.docker.internal}"
  endpoint="${endpoint/http:\/\/[::1]/http:\/\/host.docker.internal}"
  printf '%s\n' "$endpoint"
}

docker_cli() {
  local verbose_args=()
  if [[ "$MICROCKS_VERBOSE" == "true" ]]; then
    verbose_args+=(--verbose)
  fi

  docker run --rm \
    --user 0:0 \
    --add-host=host.docker.internal:host-gateway \
    -v "$ROOT_DIR:$ROOT_DIR" \
    -w "$ROOT_DIR" \
    "$MICROCKS_IMAGE" \
    "$MICROCKS_COMMAND" "${verbose_args[@]}" "$@"
}

wait_for_managed_microcks() {
  local timeout_secs
  local deadline
  timeout_secs="$(duration_seconds "$MICROCKS_READY_TIMEOUT")"
  deadline=$((SECONDS + timeout_secs))

  until curl -fsS "http://localhost:${MICROCKS_MANAGED_PORT}/api/health" >/dev/null 2>&1 \
    || curl -fsS "http://localhost:${MICROCKS_MANAGED_PORT}/" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for Microcks on http://localhost:${MICROCKS_MANAGED_PORT}" >&2
      docker logs "$MICROCKS_MANAGED_CONTAINER" >&2 || true
      exit 14
    fi
    sleep 2
  done
}

start_managed_microcks() {
  require_command docker
  require_command curl

  if [[ -n "$MICROCKS_MANAGED_CONTAINER" ]]; then
    return
  fi

  MICROCKS_MANAGED_CONTAINER="status-list-microcks-$$"
  echo "Starting Microcks on http://localhost:${MICROCKS_MANAGED_PORT} (${MICROCKS_UBER_IMAGE})"
  docker run -d --rm \
    --name "$MICROCKS_MANAGED_CONTAINER" \
    --add-host=host.docker.internal:host-gateway \
    -p "${MICROCKS_MANAGED_PORT}:8080" \
    "$MICROCKS_UBER_IMAGE" >/dev/null

  wait_for_managed_microcks
}

run_microcks_with_managed_server() {
  local runner="$1"
  local operations_headers="$2"
  local openapi_artifact="$3"
  local postman_artifact="$4"
  local microcks_url="http://host.docker.internal:${MICROCKS_MANAGED_PORT}/api/"
  local test_endpoint

  start_managed_microcks
  test_endpoint="$(endpoint_for_container "$API_ENDPOINT")"

  docker_cli import "${openapi_artifact}:true,${postman_artifact}:false" \
    --microcksURL="$microcks_url" \
    --keycloakClientId=foo \
    --keycloakClientSecret=bar

  docker_cli test \
    "$API_NAME_VERSION" \
    "$test_endpoint" \
    "$runner" \
    --microcksURL="$microcks_url" \
    --keycloakClientId=foo \
    --keycloakClientSecret=bar \
    --waitFor="$MICROCKS_WAIT_FOR" \
    --operationsHeaders="$operations_headers"
}

run_microcks() {
  local artifact="$1"
  local runner="$2"
  local operations_headers="$3"
  local verbose_args=()
  if [[ "$MICROCKS_VERBOSE" == "true" ]]; then
    verbose_args+=(--verbose)
  fi

  if command -v microcks >/dev/null 2>&1; then
    microcks "${verbose_args[@]}" test --dry-run \
      --artifact "$artifact" \
      "$API_NAME_VERSION" \
      "$API_ENDPOINT" \
      "$runner" \
      --ready-timeout="$MICROCKS_READY_TIMEOUT" \
      --waitFor="$MICROCKS_WAIT_FOR" \
      --operationsHeaders="$operations_headers"
    return
  fi

  if command -v microcks-cli >/dev/null 2>&1; then
    microcks-cli "${verbose_args[@]}" test --dry-run \
      --artifact "$artifact" \
      "$API_NAME_VERSION" \
      "$API_ENDPOINT" \
      "$runner" \
      --ready-timeout="$MICROCKS_READY_TIMEOUT" \
      --waitFor="$MICROCKS_WAIT_FOR" \
      --operationsHeaders="$operations_headers"
    return
  fi

  run_microcks_with_managed_server "$runner" "$operations_headers" "$artifact" "$MICROCKS_POSTMAN_ARTIFACT"
}

require_command node
require_command curl
token_data_file="$(mktemp)"
generate_token_data "$token_data_file"

if [[ -z "${STATUS_LIST_AUTH_TOKEN:-}" ]]; then
  register_generated_issuer "$token_data_file"
  STATUS_LIST_AUTH_TOKEN="$(json_field "$token_data_file" token)"
fi

OPERATIONS_HEADERS="${MICROCKS_OPERATIONS_HEADERS:-$(build_operations_headers)}"
MICROCKS_OPENAPI_ARTIFACT="${MICROCKS_OPENAPI_ARTIFACT:-$(prepare_microcks_openapi_artifact)}"
MICROCKS_POSTMAN_ARTIFACT="${MICROCKS_POSTMAN_ARTIFACT:-$(prepare_microcks_postman_artifact)}"

echo "Running Microcks OpenAPI schema conformance test against $API_ENDPOINT"
run_microcks "$MICROCKS_OPENAPI_ARTIFACT" "OPEN_API_SCHEMA" "$OPERATIONS_HEADERS"

if [[ "$RUN_POSTMAN_CONFORMANCE" == "true" ]]; then
  echo "Running Microcks Postman conformance test against $API_ENDPOINT"
  run_microcks "$POSTMAN_ARTIFACT" "POSTMAN" "$OPERATIONS_HEADERS"
else
  echo "Skipping Microcks Postman runner (set RUN_POSTMAN_CONFORMANCE=true to enable it); collection is still imported into Microcks."
fi
