#!/usr/bin/env bash
# Exercise the released chart and image against the candidate on one database.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <previous-chart> <candidate-chart> <previous-digest> <candidate-digest>" >&2
  exit 2
fi

previous_chart=$1
candidate_chart=$2
previous_digest=$3
candidate_digest=$4
namespace=direct-upgrade
release=statuslist
image=ghcr.io/adorsys/status-list-server

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

deployment="${release}-status-list-server-deployment"
kubectl create namespace "$namespace"

helm install "$release" "$previous_chart" -n "$namespace" \
  -f "$previous_chart/values-local.yaml" \
  --set-string "statuslist.image.repository=$image" \
  --set-string "statuslist.image.digest=$previous_digest" \
  --wait --timeout 10m
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m

quota_present=$(psql_in_cluster "SELECT to_regclass('public.list_quota') IS NOT NULL")
if [[ $(psql_in_cluster "SELECT to_regclass('public.issuers') IS NOT NULL") == t ]]; then
  psql_in_cluster "INSERT INTO issuers (issuer, aggregation_id) VALUES ('upgrade-fixture', '11111111-1111-4111-8111-111111111111')"
fi

psql_in_cluster "$(cat <<'SQL'
INSERT INTO credentials (issuer, public_key) VALUES (
  'upgrade-fixture',
  '{"kty":"EC","crv":"P-256","alg":"ES256","kid":"upgrade-fixture-key","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}'
);
INSERT INTO status_lists (list_id, issuer, status_list, sub, updated_at) VALUES (
  'upgrade-fixture-list', 'upgrade-fixture', '{"bits":1,"lst":"eJxjAAAAAQAB"}',
  'upgrade-fixture-sub', 1700000000
);
SQL
)"
if [[ "$quota_present" == t ]]; then
  psql_in_cluster "UPDATE issuers SET list_count = 1 WHERE issuer = 'upgrade-fixture'"
fi
before=$(psql_in_cluster 'SELECT COUNT(*) FROM seaql_migrations')

upgrade_args=()
if [[ "$quota_present" == f ]]; then
  upgrade_args+=(--set-string statuslist.env.APP_LIMITS__LIST_QUOTA_TRANSITION=true)
fi

helm upgrade "$release" "$candidate_chart" -n "$namespace" \
  -f "$candidate_chart/values-local.yaml" \
  --set statuslist.strategy.type=Recreate \
  --set-string "statuslist.image.repository=$image" \
  --set-string "statuslist.image.digest=$candidate_digest" \
  "${upgrade_args[@]}" \
  --wait --timeout 10m
kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout 2m

if [[ "$quota_present" == f ]]; then
  kubectl exec -n "$namespace" "deployment/$deployment" -- /app/status-list-server list-quota recount
  kubectl exec -n "$namespace" "deployment/$deployment" -- /app/status-list-server list-quota enable
  helm upgrade "$release" "$candidate_chart" -n "$namespace" \
    -f "$candidate_chart/values-local.yaml" \
    --set statuslist.strategy.type=Recreate \
    --set-string "statuslist.image.repository=$image" \
    --set-string "statuslist.image.digest=$candidate_digest" \
    --wait --timeout 10m
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
[[ $(psql_in_cluster "SELECT list_count FROM issuers WHERE issuer = 'upgrade-fixture'") == 1 ]] || {
  echo "::error::The upgraded issuer's list count was not backfilled."
  exit 1
}

if ! pod=$(kubectl get pods -n "$namespace" \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=status-list-server" -o json \
  | jq -er --arg image "$image@$candidate_digest" \
    'first(.items[] | select(.spec.containers[0].image == $image) | .metadata.name)'); then
  echo "::error::No pod uses the candidate image digest."
  exit 1
fi
kubectl wait -n "$namespace" --for=condition=Ready "pod/$pod" --timeout=2m
echo "Direct upgrade passed: $before to $after applied migration records, fixture preserved, candidate pod ready."
