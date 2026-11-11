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

deployment="${release}-status-list-server-deployment"
kubectl create namespace "$namespace"
kubectl create configmap direct-upgrade-issuers -n "$namespace" \
  --from-file=issuers.yaml=scripts/direct-upgrade-issuers.yaml

helm install "$release" "$previous_chart" -n "$namespace" \
  -f "$values" \
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
psql_in_cluster "$(cat <<'SQL'
INSERT INTO credentials (issuer, public_key) VALUES (
  'upgrade-fixture',
  '{"kty":"EC","crv":"P-256","alg":"ES256","kid":"upgrade-fixture-key","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}'
);
INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at) VALUES (
  'upgrade-fixture-list', 'upgrade-fixture', '{"bits":1,"lst":"eJxjAAAAAQAB"}',
  'upgrade-fixture-sub', 1700000000
);
INSERT INTO credentials (issuer, public_key)
SELECT 'upgrade-load-' || n,
  '{"kty":"EC","crv":"P-256","alg":"ES256","kid":"upgrade-fixture-key","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}'
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
helm upgrade "$release" "$candidate_chart" -n "$namespace" \
  -f "$values" \
  --set-string "statuslist.image.repository=$image" \
  --set-string "statuslist.image.digest=$candidate_digest" \
  "${upgrade_args[@]}" \
  --wait --timeout 5m
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m
assert_candidate_ready
echo "Candidate first Ready after $(($(date +%s) - upgrade_started)) seconds with 3001 seeded lists."

if [[ "$quota_present" == f ]]; then
  kubectl exec -n "$namespace" "deployment/$deployment" -- /app/status-list-server list-quota recount
  kubectl exec -n "$namespace" "deployment/$deployment" -- /app/status-list-server list-quota enable
  helm upgrade "$release" "$candidate_chart" -n "$namespace" \
    -f "$values" \
    --set-string "statuslist.image.repository=$image" \
    --set-string "statuslist.image.digest=$candidate_digest" \
    --wait --timeout 5m
  kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m
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
[[ $(psql_in_cluster "SELECT COUNT(*) FROM status_lists WHERE issuer LIKE 'upgrade-load-%'") == 3000 ]] || {
  echo "::error::The pre-upgrade load fixture was not preserved."
  exit 1
}
if [[ "$issuers_present" == t ]]; then
  [[ $(psql_in_cluster "SELECT aggregation_id FROM issuers WHERE issuer = 'upgrade-fixture'") == "$aggregation_before" ]] || {
    echo "::error::The pre-upgrade aggregation ID changed."
    exit 1
  }
fi
if [[ "$quota_present" == f ]]; then
  [[ $(psql_in_cluster "SELECT list_count FROM issuers WHERE issuer = 'upgrade-fixture'") == 1 ]] || {
    echo "::error::The upgraded issuer's list count was not backfilled."
    exit 1
  }
fi

assert_candidate_ready

port_forward_log=$(mktemp)
headers=$(mktemp)
kubectl port-forward -n "$namespace" "pod/$pod" 18080:8000 > "$port_forward_log" 2>&1 &
port_forward_pid=$!
trap 'kill "$port_forward_pid" 2>/dev/null || true; rm -f "$port_forward_log" "$headers"' EXIT
http_status=
for _ in {1..20}; do
  http_status=$(curl --silent --show-error --output /dev/null --dump-header "$headers" \
    --write-out '%{http_code}' --header 'Accept: application/statuslist+jwt' \
    http://127.0.0.1:18080/api/v1/status-lists/upgrade-fixture-list 2>/dev/null || true)
  [[ "$http_status" == 200 ]] && break
  if ! kill -0 "$port_forward_pid" 2>/dev/null; then
    cat "$port_forward_log" >&2
    break
  fi
  sleep 1
done
[[ "$http_status" == 200 ]] || { echo "::error::The candidate did not serve the pre-upgrade list (HTTP ${http_status:-none})."; exit 1; }
grep -iq '^content-type: application/statuslist+jwt' "$headers" || {
  echo "::error::The candidate served the pre-upgrade list with the wrong content type."
  exit 1
}
echo "Direct upgrade passed: $before to $after applied migration records, fixture preserved, candidate pod ready."
