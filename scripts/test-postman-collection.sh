#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_ENDPOINT="${API_ENDPOINT:-http://localhost:8000}"
POSTMAN_COLLECTION="${POSTMAN_COLLECTION:-postman/status-list-server.postman_collection.json}"
POSTMAN_ENVIRONMENT="${POSTMAN_ENVIRONMENT:-postman/status-list-server.postman_environment.json}"
NEWMAN_TIMEOUT_REQUEST="${NEWMAN_TIMEOUT_REQUEST:-10000}"
NEWMAN_API_READY_TIMEOUT="${NEWMAN_API_READY_TIMEOUT:-180}"
NEWMAN_RUNNER="${NEWMAN_RUNNER:-auto}"
NEWMAN_DOCKER_IMAGE="${NEWMAN_DOCKER_IMAGE:-postman/newman@sha256:02dc4a285dc05aa3a3f4035e5425a83f3b4cdb21afb71c79df589cbac0a0e04f}"

tmp_dir=""
cleanup() {
  if [[ -n "${tmp_dir:-}" ]]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

wait_for_api() {
  local deadline=$((SECONDS + NEWMAN_API_READY_TIMEOUT))
  until curl -fsS "$API_ENDPOINT/health/live" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for status-list-server at $API_ENDPOINT" >&2
      exit 14
    fi
    sleep 2
  done
}

endpoint_for_container() {
  local endpoint="$1"
  endpoint="${endpoint/http:\/\/localhost/http:\/\/host.docker.internal}"
  endpoint="${endpoint/http:\/\/127.0.0.1/http:\/\/host.docker.internal}"
  endpoint="${endpoint/http:\/\/[::1]/http:\/\/host.docker.internal}"
  printf '%s\n' "$endpoint"
}

select_newman_runner() {
  case "$NEWMAN_RUNNER" in
    local)
      require_command newman
      SELECTED_NEWMAN_RUNNER="local"
      NEWMAN_COMMAND="newman"
      COLLECTION_ENDPOINT="$API_ENDPOINT"
      ;;
    docker)
      require_command docker
      SELECTED_NEWMAN_RUNNER="docker"
      COLLECTION_ENDPOINT="$(endpoint_for_container "$API_ENDPOINT")"
      ;;
    auto)
      if [[ -x "$ROOT_DIR/node_modules/.bin/newman" ]]; then
        SELECTED_NEWMAN_RUNNER="local"
        NEWMAN_COMMAND="$ROOT_DIR/node_modules/.bin/newman"
        COLLECTION_ENDPOINT="$API_ENDPOINT"
      elif command -v newman >/dev/null 2>&1; then
        SELECTED_NEWMAN_RUNNER="local"
        NEWMAN_COMMAND="newman"
        COLLECTION_ENDPOINT="$API_ENDPOINT"
      else
        require_command docker
        SELECTED_NEWMAN_RUNNER="docker"
        COLLECTION_ENDPOINT="$(endpoint_for_container "$API_ENDPOINT")"
      fi
      ;;
    *)
      echo "NEWMAN_RUNNER must be one of: auto, local, docker" >&2
      exit 1
      ;;
  esac
}

generate_postman_artifacts() {
  local collection_out="$1"
  local environment_out="$2"

  node - "$POSTMAN_COLLECTION" "$POSTMAN_ENVIRONMENT" "$collection_out" "$environment_out" "$COLLECTION_ENDPOINT" <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

const [collectionFile, environmentFile, collectionOut, environmentOut, baseUrl] = process.argv.slice(2);
const collection = JSON.parse(fs.readFileSync(collectionFile, 'utf8'));
const environment = JSON.parse(fs.readFileSync(environmentFile, 'utf8'));

const now = Math.floor(Date.now() / 1000);
const issuerId = `newman-issuer-${Date.now()}`;
const listId = crypto.randomUUID();

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
const token = `${signingInput}.${base64url(signature)}`;
const publicKeyJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });

function visitItems(items, visitor) {
  for (const item of items || []) {
    visitor(item);
    if (item.item) visitItems(item.item, visitor);
  }
}

visitItems(collection.item, (item) => {
  if (item.name === 'Register issuer credentials' && item.request?.body?.raw) {
    item.request.body.raw = JSON.stringify({
      issuer: issuerId,
      public_key: publicKeyJwk,
    }, null, 2);
  }
});

const values = new Map([
  ['baseUrl', baseUrl],
  ['list_id', listId],
  ['issuer_id', issuerId],
  ['token', token],
]);

for (const variable of collection.variable || []) {
  if (values.has(variable.key)) variable.value = values.get(variable.key);
}

for (const variable of environment.values || []) {
  if (values.has(variable.key)) {
    variable.value = values.get(variable.key);
    variable.enabled = true;
  }
}

environment.name = `${environment.name || 'status-list-server'} - Newman`;
fs.writeFileSync(collectionOut, JSON.stringify(collection, null, 2));
fs.writeFileSync(environmentOut, JSON.stringify(environment, null, 2), { mode: 0o600 });
NODE
}

require_command node
require_command curl
select_newman_runner

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/status-list-newman.XXXXXX")"
collection_artifact="$tmp_dir/status-list-server.postman_collection.json"
environment_artifact="$tmp_dir/status-list-server.postman_environment.json"
collection_mount="/etc/newman/status-list-server.postman_collection.json"
environment_mount="/etc/newman/status-list-server.postman_environment.json"

generate_postman_artifacts "$collection_artifact" "$environment_artifact"
wait_for_api

if [[ "$SELECTED_NEWMAN_RUNNER" == "local" ]]; then
  "$NEWMAN_COMMAND" run "$collection_artifact" \
    --environment "$environment_artifact" \
    --timeout-request "$NEWMAN_TIMEOUT_REQUEST" \
    --color off
else
  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    --mount "type=bind,source=${tmp_dir},target=/etc/newman,readonly" \
    "$NEWMAN_DOCKER_IMAGE" \
    run "$collection_mount" \
    --environment "$environment_mount" \
    --timeout-request "$NEWMAN_TIMEOUT_REQUEST" \
    --color off
fi
