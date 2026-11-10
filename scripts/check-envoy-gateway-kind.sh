#!/usr/bin/env bash
# Checks the chart's Gateway API mode in a throwaway kind cluster.
# IMAGE=repo:tag skips the image build; KEEP_CLUSTER=1 keeps the cluster.
set -euo pipefail
cd "$(dirname "$0")/.."

EG_VERSION="${EG_VERSION:-v1.9.3}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.17.0@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40}"
CLUSTER="${CLUSTER:-statuslist-edge}"
IMAGE="${IMAGE:-}"
KEEP_CLUSTER="${KEEP_CLUSTER:-}"
NAMESPACE=statuslist
RELEASE=statuslist
NAME="$RELEASE-status-list-server"
HOST=statuslist.kind.test
WORK=$(mktemp -d)
# Stops Git Bash rewriting pod paths; native tools get Windows paths instead.
if command -v cygpath >/dev/null 2>&1; then
  WORK=$(cygpath -m "$WORK")
  export MSYS_NO_PATHCONV=1
fi
export KUBECONFIG="$WORK/kubeconfig"
FAILURES=0
PORT_FORWARD=""

pass() { printf 'PASS %s\n' "$*"; }
fail() {
  printf 'FAIL %s\n' "$*"
  FAILURES=$((FAILURES + 1))
}

cleanup() {
  if [ -n "$PORT_FORWARD" ]; then kill "$PORT_FORWARD" 2>/dev/null || true; fi
  if [ -n "$KEEP_CLUSTER" ]; then
    printf 'kept cluster %s; export KUBECONFIG=%s\n' "$CLUSTER" "$KUBECONFIG"
  else
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

until_equals() {
  local expected="$1"
  shift
  for _ in $(seq 90); do
    if [ "$("$@" 2>/dev/null)" = "$expected" ]; then return 0; fi
    sleep 2
  done
  printf 'timed out waiting for %s from: %s\n' "$expected" "$*" >&2
  return 1
}

status_of() {
  kubectl exec "$1" -- curl -sk -o /dev/null -w '%{http_code}' --resolve "$HOST:443:$ENVOY_IP" "https://$HOST$2"
}

request() {
  local pod="$1" method="$2" path="$3"
  shift 3
  kubectl exec "$pod" -- curl -sk -X "$method" -w ' %{http_code}' --resolve "$HOST:443:$ENVOY_IP" "$@" \
    "https://$HOST$path" | tr -d '\r'
}

# Responses stay in the pod's /tmp/out as <round>-<request>.
send() {
  local pod="$1" rounds="$2" count="$3" path="$4"
  shift 4
  kubectl exec -i "$pod" -- sh -s "$HOST" "$ENVOY_IP" "$rounds" "$count" "$path" "$@" <<'SH'
set -eu
host=$1 ip=$2 rounds=$3 count=$4 path=$5
shift 5
rm -rf /tmp/out
mkdir -p /tmp/out
round=1
while [ "$round" -le "$rounds" ]; do
  : > /tmp/requests
  i=1
  while [ "$i" -le "$count" ]; do
    printf 'url = "https://%s%s"\noutput = "/tmp/out/%03d-%04d"\n' "$host" "$path" "$round" "$i" >> /tmp/requests
    i=$((i + 1))
  done
  curl -sk -i --resolve "$host:443:$ip" "$@" --config /tmp/requests || true
  round=$((round + 1))
  if [ "$round" -le "$rounds" ]; then sleep 1; fi
done
for response in /tmp/out/*; do
  head -n 1 "$response" | cut -d ' ' -f 2
done
SH
}

response_of() { kubectl exec "$1" -- cat "/tmp/out/$2" | tr -d '\r'; }

first_with_status() {
  kubectl exec "$1" -- sh -c "grep -l '^HTTP/[0-9.]* $2' /tmp/out/* | head -n 1 | xargs cat" | tr -d '\r'
}

header() {
  awk -v name="$1" 'NR > 1 && $0 == "" { exit }
    NR > 1 { split($0, field, ": "); if (tolower(field[1]) == name) print substr($0, length(field[1]) + 3) }'
}

body() { awk 'found { print } $0 == "" { found = 1 }'; }

status_list_requests() {
  curl -s http://127.0.0.1:18002/metrics | awk '
    index($0, "http_server_requests_total{") == 1 && index($0, "listener=\"public\"") &&
      index($0, "status-lists/{list_id}\"") { sum += $NF }
    END { print sum + 0 }'
}

kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 120s

if [ -z "$IMAGE" ]; then
  IMAGE=status-list-server:kind-check
  docker build --build-arg FEATURES=postgres,redis --tag "$IMAGE" .
fi
kind load docker-image "$IMAGE" --name "$CLUSTER"

# Local limits only; the rate limit service needs a Redis.
helm install eg oci://docker.io/envoyproxy/gateway-helm --version "$EG_VERSION" \
  --namespace envoy-gateway-system --create-namespace \
  -f deploy/helm/envoy-gateway.yaml --set config.envoyGateway.rateLimit=null --wait --timeout 5m

(cd "$WORK" && openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" -keyout tls.key -out tls.crt 2>/dev/null)
kubectl --namespace envoy-gateway-system create secret tls statuslist-tls \
  --cert "$WORK/tls.crt" --key "$WORK/tls.key"
kubectl create namespace "$NAMESPACE"
kubectl apply -f deploy/helm/envoy-gateway-platform.yaml

if ! ls deploy/helm/chart/charts/*.tgz >/dev/null 2>&1; then
  helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts >/dev/null
  helm dependency build deploy/helm/chart >/dev/null
fi
helm install "$RELEASE" deploy/helm/chart --namespace "$NAMESPACE" \
  -f deploy/helm/chart/values-envoy-gateway.yaml -f scripts/testdata/envoy-gateway-kind.yaml \
  --set statuslist.image.repository="${IMAGE%:*}" --set statuslist.image.tag="${IMAGE##*:}" \
  --wait --timeout 10m

kubectl --namespace envoy-gateway-system wait deployment --for condition=Available --timeout 180s \
  --selector gateway.envoyproxy.io/owning-gateway-name=statuslist
for route in "$NAME-route" "$NAME-management-route"; do
  until_equals True kubectl --namespace "$NAMESPACE" get "httproute/$route" \
    -o 'jsonpath={.status.parents[0].conditions[?(@.type=="Accepted")].status}'
  until_equals True kubectl --namespace "$NAMESPACE" get "backendtrafficpolicy/$route" \
    -o 'jsonpath={.status.ancestors[0].conditions[?(@.type=="Accepted")].status}'
done

for client in client-a client-b client-c; do
  kubectl run "$client" --image "$CURL_IMAGE" --restart Never --command -- sleep 3600 >/dev/null
done
kubectl wait pod/client-a pod/client-b pod/client-c --for condition=Ready --timeout 120s >/dev/null
ENVOY_IP=$(kubectl --namespace envoy-gateway-system get service \
  --selector gateway.envoyproxy.io/owning-gateway-name=statuslist -o 'jsonpath={.items[0].spec.clusterIP}')
until_equals 200 status_of client-a /
until_equals 401 status_of client-a /api/v1/credentials

kubectl --namespace "$NAMESPACE" port-forward "service/$NAME-internal-service" 18002:8002 >/dev/null 2>&1 &
PORT_FORWARD=$!
until_equals 200 curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18002/health/ready

printf '== edge limit: client-a floods the public route while client-b reads\n'
before=$(status_list_requests)
send client-a 5 300 /api/v1/status-lists/kind-check --parallel --parallel-max 50 >"$WORK/a.codes" &
flood=$!
sleep 1
send client-b 1 5 / --rate 1/s >"$WORK/b.codes"
wait "$flood"
after=$(status_list_requests)
total=$(wc -l <"$WORK/a.codes" | tr -d ' ')
limited=$(grep -c '^429$' "$WORK/a.codes" || true)
reached=$(grep -c '^404$' "$WORK/a.codes" || true)
other=$((total - limited - reached))
if [ "$total" -eq 1500 ] && [ "$limited" -gt 0 ] && [ "$other" -eq 0 ]; then
  pass "client-a got $limited edge 429s and $reached server 404s out of 1500"
else
  fail "client-a: $total responses, $limited 429, $reached 404, $other other"
fi
if [ "$(sort -u "$WORK/b.codes")" = "200" ] && [ "$(wc -l <"$WORK/b.codes" | tr -d ' ')" -eq 5 ]; then
  pass "client-b was not limited while client-a was"
else
  fail "client-b got: $(tr '\n' ' ' <"$WORK/b.codes")"
fi
if [ "$reached" -gt 0 ] && [ "$((after - before))" -eq "$reached" ]; then
  pass "the server counted exactly the $reached requests Envoy let through"
else
  fail "the server counted $((after - before)) status-list requests, Envoy let $reached through"
fi

edge=$(first_with_status client-a 429)
expected=$(kubectl --namespace "$NAMESPACE" get "backendtrafficpolicy/$NAME-route" \
  -o 'jsonpath={.spec.responseOverride[0].response.body.inline}')
if [ "$(printf '%s\n' "$edge" | body)" = "$expected" ] &&
  [ "$(printf '%s\n' "$edge" | header content-type)" = "application/json" ] &&
  [ "$(printf '%s\n' "$edge" | header retry-after)" = "1" ] &&
  [ "$(printf '%s\n' "$edge" | header cache-control)" = "no-store, max-age=0" ]; then
  pass "the edge 429 carries the policy's JSON body, Retry-After: 1 and Cache-Control"
else
  fail "edge 429 differs from the policy: $edge"
fi
forwarded=$(first_with_status client-a 404)
if [ -z "$edge" ] || [ -z "$forwarded" ]; then
  fail "no edge 429 or forwarded 404 to inspect for X-RateLimit headers"
elif printf '%s\n%s\n' "$edge" "$forwarded" | grep -qi '^x-ratelimit'; then
  fail "Envoy added X-RateLimit headers"
else
  pass "no X-RateLimit headers on edge 429s or forwarded responses"
fi

printf '== routing on the shared host\n'
expect() {
  local what="$1" status="$2" error="$3" out
  shift 3
  out=$(request client-c "$@")
  if [ "${out##* }" = "$status" ] && { [ -z "$error" ] || printf '%s' "$out" | grep -q "\"error\":\"$error\""; }; then
    pass "$what (${out##* })"
  else
    fail "$what: expected $status $error, got: $out"
  fi
}
expect "a status write reaches the management listener" 401 missing_token \
  PUT /api/v1/status-lists/kind-route/statuses -H 'Content-Type: application/json' --data '{}'
expect "credentials reach the management listener" 401 missing_token GET /api/v1/credentials
expect "status-list reads stay on the public listener" 404 status_list_not_found \
  GET /api/v1/status-lists/kind-route
expect "readiness is not routed" 404 "" GET /health/ready
expect "the admin API is not routed" 404 "" GET /admin/v1/issuers

printf '== server 429s pass through\n'
codes=$(send client-b 1 11 /api/v1/credentials --rate 5/s -H 'Authorization: Bearer not-a-jwt' | tr '\n' ' ')
server=$(response_of client-b 001-0011)
retry_after=$(printf '%s\n' "$server" | header retry-after)
if [ "$codes" = "401 401 401 401 401 401 401 401 401 401 429 " ] &&
  printf '%s\n' "$server" | body | grep -q 'Too many failed authentications from this address' &&
  [ "${retry_after:-0}" -gt 1 ] &&
  [ "$(printf '%s\n' "$server" | header cache-control)" = "no-store, max-age=0" ] &&
  ! printf '%s\n' "$server" | grep -qi '^x-ratelimit'; then
  pass "the server's own 429 arrives unchanged (Retry-After: $retry_after)"
else
  fail "server 429 pass-through: codes [$codes], response: $server"
fi

printf '== network policy\n'
POD_IP=$(kubectl --namespace "$NAMESPACE" get pod -o 'jsonpath={.items[0].status.podIP}' \
  --selector "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/name=status-list-server")
if kubectl exec client-c -- curl -s -o /dev/null --max-time 5 "http://$POD_IP:8000/health/live"; then
  printf 'NOTE this CNI let client-c reach the server pod directly; the NetworkPolicy is not verified here\n'
else
  pass "a direct request to the server pod's public port is refused"
fi

if [ "$FAILURES" -gt 0 ]; then
  printf '%s check(s) failed\n' "$FAILURES"
  exit 1
fi
printf 'all checks passed\n'
