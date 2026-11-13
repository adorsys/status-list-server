#!/usr/bin/env bash
# Exercise the released chart and image against the candidate on one database.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <previous-chart> <candidate-chart> <previous-digest> <candidate-digest> <image-base>" >&2
  exit 2
fi

previous_chart=$1
candidate_chart=$2
previous_digest=$3
candidate_digest=$4
namespace=direct-upgrade
release=statuslist
image=$5
values=scripts/direct-upgrade-values.yaml
candidate_values=scripts/direct-upgrade-candidate-values.yaml
fixture_dir=$(mktemp -d)
port_forward_pid=
cleanup() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_dir"
}
trap cleanup EXIT
node scripts/generate-direct-upgrade-fixture.js prepare "$fixture_dir"
cert_args=(
  --set-file 'statuslist.fallbackSecret.stringData.statuslist\.crt=test_data/certs/dev.crt'
  --set-file 'statuslist.fallbackSecret.stringData.statuslist\.key=test_data/certs/dev.key'
)

for digest in "$previous_digest" "$candidate_digest"; do
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
    echo "::error::An image digest is missing or malformed."
    exit 1
  }
done

psql_in_cluster() {
  kubectl exec -n "$namespace" statefulset/statuslist-postgres -c postgres -- \
    sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U postgres -d status-list -v ON_ERROR_STOP=1 -Atc "$1"' sh "$1"
}

assert_candidate_ready() {
  if ! pod=$(kubectl get pods -n "$namespace" \
    -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=status-list-server" -o json \
    | jq -er --arg image "$image@$candidate_digest" \
      'first(.items[] | select(.metadata.deletionTimestamp == null and .spec.containers[0].image == $image) | .metadata.name)'); then
    echo "::error::No live pod uses the candidate image digest."
    exit 1
  fi
  kubectl wait -n "$namespace" --for=condition=Ready "pod/$pod" --timeout=2m
  restarts=$(kubectl get pod "$pod" -n "$namespace" -o json \
    | jq '[.status.containerStatuses[]?.restartCount] + [.status.initContainerStatuses[]?.restartCount] | add // 0')
  [[ "$restarts" == 0 ]] || { echo "::error::Candidate pod restarted $restarts time(s)."; exit 1; }
}

fetch_list() {
  local target_pod=$1 body=$2 headers="$fixture_dir/headers" status=
  kubectl port-forward -n "$namespace" "pod/$target_pod" 18080:8000 > "$fixture_dir/port-forward.log" 2>&1 &
  port_forward_pid=$!
  for _ in {1..20}; do
    status=$(curl --silent --show-error --output "$body" --dump-header "$headers" \
      --write-out '%{http_code}' --header 'Accept: application/statuslist+jwt' \
      http://127.0.0.1:18080/api/v1/status-lists/upgrade-fixture-list 2>/dev/null || true)
    [[ "$status" == 200 ]] && break
    if ! kill -0 "$port_forward_pid" 2>/dev/null; then
      cat "$fixture_dir/port-forward.log" >&2
      break
    fi
    sleep 1
  done
  kill "$port_forward_pid" 2>/dev/null || true
  wait "$port_forward_pid" 2>/dev/null || true
  port_forward_pid=
  [[ "$status" == 200 ]] || { echo "::error::Pod $target_pod did not serve the seeded list (HTTP ${status:-none})."; exit 1; }
  grep -iq '^content-type: application/statuslist+jwt' "$headers" || {
    echo "::error::Pod $target_pod served the list with the wrong content type."
    exit 1
  }
}

list_fields() {
  node -e 'const fs=require("node:fs"); const jwt=fs.readFileSync(process.argv[1], "utf8").trim(); const body=JSON.parse(Buffer.from(jwt.split(".")[1], "base64url")); if (!body.status_list?.lst || !body.sub) process.exit(1); process.stdout.write(JSON.stringify({bits:body.status_list.bits,lst:body.status_list.lst,sub:body.sub}));' "$1"
}

deployment="${release}-status-list-server-deployment"
kubectl create namespace "$namespace"
kubectl create configmap direct-upgrade-issuers -n "$namespace" \
  --from-file="issuers.yaml=$fixture_dir/issuers.yaml"

helm install "$release" "$previous_chart" -n "$namespace" \
  -f "$values" \
  "${cert_args[@]}" \
  --set-string "statuslist.image.repository=$image" \
  --set-string "statuslist.image.digest=$previous_digest" \
  --wait --timeout 5m
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m

quota_present=$(psql_in_cluster "SELECT to_regclass('public.list_quota') IS NOT NULL")
issuers_present=$(psql_in_cluster "SELECT to_regclass('public.issuers') IS NOT NULL")
if [[ "$issuers_present" == t ]]; then
  psql_in_cluster "INSERT INTO issuers (issuer, aggregation_id) VALUES ('upgrade-fixture', '11111111-1111-4111-8111-111111111111')"
  psql_in_cluster "INSERT INTO issuers (issuer, aggregation_id) SELECT 'upgrade-load-' || n, ('11111111-1111-4111-8111-' || lpad(n::text, 12, '0'))::uuid FROM generate_series(1, 3) AS n"
  aggregation_before=$(psql_in_cluster "SELECT aggregation_id FROM issuers WHERE issuer = 'upgrade-fixture'")
fi

# Keep this seed compatible with the previous release's schema; it must be written before upgrading.
fixture_jwk=$(cat "$fixture_dir/public-jwk.json")
psql_in_cluster "INSERT INTO credentials (issuer, public_key) VALUES ('upgrade-fixture', '$fixture_jwk'::json)"
psql_in_cluster "$(cat <<'SQL'
INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at) VALUES (
  'upgrade-fixture-list', 'upgrade-fixture', '{"bits":1,"lst":"eJxjAAAAAQAB"}',
  'upgrade-fixture-sub', 1700000000
);
INSERT INTO credentials (issuer, public_key)
SELECT 'upgrade-load-' || n,
  CASE WHEN n = 1
    THEN '{"kty":"EC","crv":"P-256","alg":"ES256","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}'::json
    ELSE format('{"kty":"EC","crv":"P-256","alg":"ES256","kid":"upgrade-load-key-%s","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}', n)::json END
FROM generate_series(1, 3) AS n;
INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at)
SELECT 'upgrade-load-' || issuer_n || '-' || list_n,
  'upgrade-load-' || issuer_n,
  '{"bits":1,"lst":"eJxjAAAAAQAB"}',
  'upgrade-load-sub-' || issuer_n || '-' || list_n,
  1700000000
FROM generate_series(1, 3) AS issuer_n
CROSS JOIN generate_series(1, 1000) AS list_n;
SQL
)"
[[ $(psql_in_cluster "SELECT COUNT(*) = 4 AND COUNT(DISTINCT public_key->>'kid') = 3 AND COUNT(*) FILTER (WHERE public_key->>'kid' IS NULL) = 1 FROM credentials WHERE issuer LIKE 'upgrade-%'") == t ]] || {
  echo "::error::Pre-upgrade credential key fixture is invalid."
  exit 1
}
inventory=$(psql_in_cluster "$(cat <<'SQL'
WITH keys AS (
  SELECT issuer, public_key ->> 'kid' AS kid, public_key ->> 'alg' AS alg,
         jsonb_typeof(public_key::jsonb -> 'kid') AS kid_type,
         jsonb_typeof(public_key::jsonb -> 'alg') AS alg_type,
         public_key ->> 'kty' AS kty, public_key ->> 'crv' AS crv
  FROM credentials
), inventory AS (
  SELECT *, COUNT(*) OVER (PARTITION BY kid) AS duplicate_kid_count FROM keys
)
SELECT issuer FROM inventory
WHERE kid IS NULL OR kid = '' OR length(kid) > 255
   OR duplicate_kid_count > 1 OR alg IS NULL
   OR kid_type <> 'string' OR alg_type <> 'string'
   OR NOT COALESCE(((kty = 'EC' AND crv = 'P-256' AND alg = 'ES256')
        OR (kty = 'EC' AND crv = 'P-384' AND alg = 'ES384')
        OR (kty = 'OKP' AND crv = 'Ed25519' AND alg = 'EdDSA')
        OR (kty = 'RSA' AND alg = 'PS256')), FALSE);
SQL
)")
[[ "$inventory" == upgrade-load-1 ]] || {
  echo "::error::Pre-upgrade key inventory found unexpected anomalies: $inventory"
  exit 1
}
baseline_row=$(psql_in_cluster "SELECT status_list::text || '|' || sub FROM status_lists WHERE list_id = 'upgrade-fixture-list'")
old_pod=$(kubectl get pods -n "$namespace" \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=status-list-server" -o json \
  | jq -er 'first(.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name)')
fetch_list "$old_pod" "$fixture_dir/old-list.jwt"
old_fields=$(list_fields "$fixture_dir/old-list.jwt")
if [[ "$quota_present" == t ]]; then
  psql_in_cluster "UPDATE issuers SET list_count = 1 WHERE issuer = 'upgrade-fixture'"
  psql_in_cluster "UPDATE issuers SET list_count = 1000 WHERE issuer LIKE 'upgrade-load-%'"
fi
before=$(psql_in_cluster 'SELECT COUNT(*) FROM seaql_migrations')

upgrade_args=()
if [[ "$quota_present" == f ]]; then
  # See docs/troubleshooting.md, "Upgrading to the list quota"; remove when the baseline includes it.
  upgrade_args+=(--set-string statuslist.env.APP_LIMITS__LIST_QUOTA_TRANSITION=true)
fi

upgrade_started=$(date +%s)
kubectl patch deployment "$deployment" -n "$namespace" --type=json \
  -p '[{"op":"replace","path":"/spec/strategy","value":{"type":"Recreate"}}]'
helm upgrade "$release" "$candidate_chart" -n "$namespace" \
  -f "$values" \
  -f "$candidate_values" \
  "${cert_args[@]}" \
  --set statuslist.strategy.type=Recreate \
  --set-string "statuslist.image.repository=$image" \
  --set-string "statuslist.image.digest=$candidate_digest" \
  "${upgrade_args[@]}" \
  --wait --timeout 5m
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m
assert_candidate_ready
ready_seconds=$(($(date +%s) - upgrade_started))
echo "Candidate first Ready after $ready_seconds seconds with 3001 seeded lists."
if ((ready_seconds >= 30)); then
  echo "::warning::Candidate Ready time is near the approximately 40-second liveness budget."
fi
fetch_list "$pod" "$fixture_dir/candidate-list.jwt"
[[ $(list_fields "$fixture_dir/candidate-list.jwt") == "$old_fields" ]] || {
  echo "::error::The candidate changed the seeded list payload."
  exit 1
}
aggregation_first=$(psql_in_cluster "SELECT aggregation_id FROM issuers WHERE issuer = 'upgrade-fixture'")
[[ -n "$aggregation_first" ]] || { echo "::error::The migrated issuer has no aggregation ID."; exit 1; }
registry_id=$(jq -r '.issuers[0].aggregation_id' "$fixture_dir/issuers.yaml")
[[ "$aggregation_first" == "$registry_id" ]] || {
  echo "::error::The candidate did not adopt the pre-upgrade registry aggregation ID."
  exit 1
}
if [[ "$issuers_present" == t && "$aggregation_first" != "$aggregation_before" ]]; then
  echo "::error::The pre-upgrade aggregation ID changed."
  exit 1
fi

if [[ "$quota_present" == f ]]; then
  kubectl exec -n "$namespace" "pod/$pod" -- /app/status-list-server list-quota recount
  kubectl exec -n "$namespace" "pod/$pod" -- /app/status-list-server list-quota enable
  helm upgrade "$release" "$candidate_chart" -n "$namespace" \
    -f "$values" \
    -f "$candidate_values" \
    "${cert_args[@]}" \
    --set statuslist.strategy.type=Recreate \
    --set-string "statuslist.image.repository=$image" \
    --set-string "statuslist.image.digest=$candidate_digest" \
    --wait --timeout 5m
  kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m
  assert_candidate_ready
  [[ $(psql_in_cluster 'SELECT enforced FROM list_quota WHERE id = 1') == t ]] || {
    echo "::error::List quota is still disabled after the upgrade."
    exit 1
  }
fi

after=$(psql_in_cluster 'SELECT COUNT(*) FROM seaql_migrations')
[[ "$after" -ge "$before" ]] || {
  echo "::error::Migration records disappeared during the upgrade."
  exit 1
}
if [[ "$quota_present" == f && "$after" -le "$before" ]]; then
  echo "::error::The upgrade did not apply the pending list quota migration."
  exit 1
fi
[[ $(psql_in_cluster "SELECT COUNT(*) FROM status_lists WHERE list_id = 'upgrade-fixture-list' AND issuer = 'upgrade-fixture'") == 1 ]] || {
  echo "::error::The pre-upgrade status list was lost."
  exit 1
}
[[ $(psql_in_cluster "SELECT status_list::text || '|' || sub FROM status_lists WHERE list_id = 'upgrade-fixture-list'") == "$baseline_row" ]] || {
  echo "::error::The seeded status_list or sub changed during upgrade."
  exit 1
}
[[ $(psql_in_cluster "SELECT COUNT(*) FROM status_lists WHERE issuer LIKE 'upgrade-load-%'") == 3000 ]] || {
  echo "::error::The pre-upgrade load fixture was not preserved."
  exit 1
}
[[ $(psql_in_cluster "SELECT aggregation_id FROM issuers WHERE issuer = 'upgrade-fixture'") == "$aggregation_first" ]] || {
  echo "::error::The upgraded issuer's aggregation ID changed."
  exit 1
}
[[ $(psql_in_cluster "SELECT COUNT(*) = 1 AND COUNT(*) FILTER (WHERE key_id IS NOT NULL AND key_id <> '') = 1 FROM credentials WHERE issuer = 'upgrade-load-1'") == t ]] || {
  echo "::error::The missing legacy key ID was not generated."
  exit 1
}
if [[ "$quota_present" == f ]]; then
  [[ $(psql_in_cluster "SELECT list_count FROM issuers WHERE issuer = 'upgrade-fixture'") == 1 ]] || {
    echo "::error::The upgraded issuer's list count was not backfilled."
    exit 1
  }
fi

kubectl rollout restart "deployment/$deployment" -n "$namespace"
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m
assert_candidate_ready
[[ $(psql_in_cluster "SELECT aggregation_id FROM issuers WHERE issuer = 'upgrade-fixture'") == "$aggregation_first" ]] || {
  echo "::error::The aggregation ID changed after candidate restart."
  exit 1
}
node scripts/generate-direct-upgrade-fixture.js token "$fixture_dir"
kubectl port-forward -n "$namespace" "pod/$pod" 18081:8001 > "$fixture_dir/management-forward.log" 2>&1 &
port_forward_pid=$!
http_status=
for _ in {1..20}; do
  http_status=$(curl --silent --show-error --output "$fixture_dir/credentials-response" \
    --write-out '%{http_code}' --header "Authorization: Bearer $(cat "$fixture_dir/token")" \
    http://127.0.0.1:18081/api/v1/credentials 2>/dev/null || true)
  [[ "$http_status" == 200 ]] && break
  sleep 1
done
kill "$port_forward_pid" 2>/dev/null || true
wait "$port_forward_pid" 2>/dev/null || true
port_forward_pid=
[[ "$http_status" == 200 ]] || { echo "::error::Migrated issuer could not authenticate (HTTP ${http_status:-none})."; exit 1; }
jq -e --arg id "$aggregation_first" '.aggregation_id == $id' "$fixture_dir/credentials-response" > /dev/null || {
  echo "::error::Management endpoint returned the wrong aggregation ID."
  exit 1
}
# Observe a full liveness interval after Ready before accepting the restart count.
sleep 45
assert_candidate_ready
echo "Direct upgrade passed: $before to $after applied migration records, fixture preserved, candidate pod ready."
