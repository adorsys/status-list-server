#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_ENDPOINT="${API_ENDPOINT:-http://localhost:8000}"
# Unset means API_ENDPOINT's host on 8001 (management) and 8002 (admin).
MANAGEMENT_URL="${MANAGEMENT_URL:-}"
ADMIN_URL="${ADMIN_URL:-}"
POSTMAN_COLLECTION="${POSTMAN_COLLECTION:-postman/status-list-server.postman_collection.json}"
POSTMAN_ENVIRONMENT="${POSTMAN_ENVIRONMENT:-postman/status-list-server.postman_environment.json}"
NEWMAN_TIMEOUT_REQUEST="${NEWMAN_TIMEOUT_REQUEST:-10000}"
NEWMAN_API_READY_TIMEOUT="${NEWMAN_API_READY_TIMEOUT:-180}"
NEWMAN_RUNNER="${NEWMAN_RUNNER:-auto}"
NEWMAN_VERIFY_REGISTRATION_MODES="${NEWMAN_VERIFY_REGISTRATION_MODES:-false}"
MANAGEMENT_AUDIENCE="${MANAGEMENT_AUDIENCE:-status-list-server-management}"
POSTMAN_ISSUER_REGISTRY_FILE="${POSTMAN_ISSUER_REGISTRY_FILE:-}"
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

  node - "$POSTMAN_COLLECTION" "$POSTMAN_ENVIRONMENT" "$collection_out" "$environment_out" "$COLLECTION_ENDPOINT" "$RESOLVED_MANAGEMENT_URL" "$RESOLVED_ADMIN_URL" "$MANAGEMENT_AUDIENCE" "$POSTMAN_ISSUER_REGISTRY_FILE" <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

const [collectionFile, environmentFile, collectionOut, environmentOut, baseUrl, mgmtUrl, adminUrl, audience, registryFile] = process.argv.slice(2);
const collection = JSON.parse(fs.readFileSync(collectionFile, 'utf8'));
const environment = JSON.parse(fs.readFileSync(environmentFile, 'utf8'));

function siblingUrl(baseUrl, port) {
  const url = new URL(baseUrl);
  url.port = port;
  return url.toString().replace(/\/$/, '');
}

const now = Math.floor(Date.now() / 1000) - 5;
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

const header = { alg: 'ES256', typ: 'statuslist-management+jwt', kid: issuerId };
const payload = { iss: issuerId, aud: audience, iat: now, exp: now + 300 };
const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
const signature = crypto.sign('sha256', Buffer.from(signingInput), {
  key: privateKey,
  dsaEncoding: 'ieee-p1363'
});
const token = `${signingInput}.${base64url(signature)}`;
const publicKeyJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
publicKeyJwk.kid = header.kid;
publicKeyJwk.alg = header.alg;

if (registryFile) {
  const registryContent = JSON.stringify({
    version: 1,
    issuers: [{
      id: issuerId,
      aggregation_id: listId,
      display_name: 'Newman test issuer',
      tier: 'standard',
      keys: [{ kid: issuerId, alg: header.alg, jwk: publicKeyJwk }],
    }],
    admins: [],
  }, null, 2);
  const temporaryRegistry = `${registryFile}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryRegistry, registryContent);
  fs.renameSync(temporaryRegistry, registryFile);
}

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
  ['managementUrl', mgmtUrl],
  ['adminUrl', adminUrl],
  ['list_id', listId],
  ['issuer_id', issuerId],
  ['token', token],
  ['issuer_public_key', JSON.stringify(publicKeyJwk)],
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
newman_202_report="$tmp_dir/newman-202-report.json"
newman_409_report="$tmp_dir/newman-409-report.json"

_sibling_url() {
  local url="$1" port="$2"
  url="${url%/}"
  if [[ "$url" =~ :[0-9]+$ ]]; then
    printf '%s\n' "${url%:*}:${port}"
  else
    printf '%s\n' "${url}:${port}"
  fi
}
if [[ -z "$MANAGEMENT_URL" ]]; then
  RESOLVED_MANAGEMENT_URL="$(_sibling_url "$COLLECTION_ENDPOINT" 8001)"
else
  RESOLVED_MANAGEMENT_URL="$(endpoint_for_container "$MANAGEMENT_URL")"
fi
if [[ -z "$ADMIN_URL" ]]; then
  RESOLVED_ADMIN_URL="$(_sibling_url "$COLLECTION_ENDPOINT" 8002)"
else
  RESOLVED_ADMIN_URL="$(endpoint_for_container "$ADMIN_URL")"
fi

generate_postman_artifacts "$collection_artifact" "$environment_artifact"
wait_for_api
if [[ -n "$POSTMAN_ISSUER_REGISTRY_FILE" ]]; then
  # Wait for the generated key to authenticate, rather than guessing how long
  # the file watcher will take on this runner.
  token="$(node -e 'const values=require(process.argv[1]).values; process.stdout.write(values.find(v=>v.key==="token").value)' "$environment_artifact")"
  if [[ -n "$MANAGEMENT_URL" ]]; then
    probe_url="${MANAGEMENT_URL%/}"
  else
    probe_url="$(_sibling_url "$API_ENDPOINT" 8001)"
  fi
  deadline=$((SECONDS + NEWMAN_API_READY_TIMEOUT))
  until [[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" "$probe_url/api/v1/credentials" 2>/dev/null || true)" == "200" ]]; do
    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for generated issuer key to authenticate" >&2
      exit 14
    fi
    sleep 1
  done
fi


run_newman() {
  local report_path="$1"
  shift
  if [[ "$SELECTED_NEWMAN_RUNNER" == "local" ]]; then
    "$NEWMAN_COMMAND" run "$collection_artifact" "$@" \
      --environment "$environment_artifact" \
      --timeout-request "$NEWMAN_TIMEOUT_REQUEST" \
      --reporters cli,json \
      --reporter-json-export "$report_path" \
      --color off
  else
    local report_name
    report_name="${report_path##*/}"
    docker run --rm \
      --add-host=host.docker.internal:host-gateway \
      --mount "type=bind,source=${tmp_dir},target=/etc/newman" \
      "$NEWMAN_DOCKER_IMAGE" \
      run "$collection_mount" "$@" \
      --environment "$environment_mount" \
      --timeout-request "$NEWMAN_TIMEOUT_REQUEST" \
      --reporters cli,json \
      --reporter-json-export "/etc/newman/$report_name" \
      --color off
  fi
}

verify_registration_report() {
  local report_path="$1" expected_code="$2"
  node - "$report_path" "$expected_code" <<'NODE'
const fs = require('node:fs');
const [reportPath, expectedCode] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const registration = report.run.executions.find(({ item }) => item.name === 'Register issuer credentials');
if (!registration) throw new Error('Newman report does not contain issuer registration.');
const mode = registration.assertions.find(({ assertion }) => assertion === 'Newman registration status matches expected response');
if (!mode || mode.skipped === true || mode.error != null) throw new Error(`Newman did not confirm an HTTP ${expectedCode} registration response.`);
const ready = registration.assertions.find(({ assertion }) => assertion === 'issuer JWT is ready for protected requests');
if (!ready || ready.skipped === true || ready.error != null) throw new Error(`Newman did not pass the issuer JWT readiness assertion for HTTP ${expectedCode}.`);
NODE
}

run_newman "$newman_202_report" --env-var expected_registration_status=202
if [[ "$NEWMAN_VERIFY_REGISTRATION_MODES" == "true" ]]; then
  verify_registration_report "$newman_202_report" 202
  # The first run registers the generated issuer. Replaying only that folder
  # exercises the real Newman 409 path without republishing its status list.
  run_newman "$newman_409_report" --env-var expected_registration_status=409 --folder "Issuer Management"
  verify_registration_report "$newman_409_report" 409
elif [[ "$NEWMAN_VERIFY_REGISTRATION_MODES" != "false" ]]; then
  echo "NEWMAN_VERIFY_REGISTRATION_MODES must be true or false" >&2
  exit 1
fi
