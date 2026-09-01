#!/usr/bin/env bash
# Alertmanager webhook-delivery tests (ticket #446).
#
# Verifies two things:
#   1. CONFIG GENERATION — `generate-alertmanager-config.sh` emits an
#      amtool-valid alertmanager.yml for EVERY supported platform
#      (webhook|discord|slack|teams|mattermost|email).
#   2. DELIVERY — a real Alertmanager, configured for the generic `webhook`
#      platform with `send_resolved: true`, actually POSTs an alert event to a
#      mock receiver for BOTH the firing and the resolved state.
#
# Requires: docker (for the prom/alertmanager image), python3.
#
# Run from the repository root:
#   observability/alertmanager/tests/test-alertmanager-config.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GENERATOR="$REPO_ROOT/observability/prometheus/generate-alertmanager-config.sh"
MOCK="$REPO_ROOT/observability/alertmanager/tests/mock_webhook.py"
AM_IMAGE="prom/alertmanager:v0.28.1"
TMP="$(mktemp -d)"
MOCK_PID=""
cleanup() {
  docker rm -f alertmanager-test >/dev/null 2>&1 || true
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
  [ -n "$MOCK_PID" ] && wait "$MOCK_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

echo "[1/2] Config generation is valid for every platform"
for PLATFORM in webhook discord slack teams mattermost email; do
  OUT="$TMP/am-$PLATFORM.yml"
  case "$PLATFORM" in
    webhook)    CREDS=(ALERTMANAGER_WEBHOOK_URL=https://hooks.example.com/status-list) ;;
    discord)    CREDS=(DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/000/aaa) ;;
    slack)      CREDS=(SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TTT/BBB/SSS) ;;
    teams)      CREDS=(MS_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/000/aaa) ;;
    mattermost) CREDS=(MATTERMOST_WEBHOOK_URL=https://mm.example.com/hooks/aaa) ;;
    email)      CREDS=(ALERTMANAGER_SMTP_HOST=smtp.example.com ALERTMANAGER_EMAIL_TO=ops@example.com) ;;
  esac
  env ALERTMANAGER_PLATFORM="$PLATFORM" ALERTMANAGER_OUT="$OUT" \
    "${CREDS[@]}" /bin/sh "$GENERATOR" >/dev/null \
      || fail "$PLATFORM: generator exited non-zero"
  docker run --rm -v "$OUT:/etc/alertmanager/alertmanager.yml:ro" \
    --entrypoint amtool "$AM_IMAGE" check-config /etc/alertmanager/alertmanager.yml \
    >/dev/null 2>&1 || fail "$PLATFORM: amtool rejected generated config"
  pass "$PLATFORM"
done

echo "[2/2] Alert delivery (firing + resolved) via generic webhook"
# Unique, realistic alert payloads to assert on in the mock sink.
ALERT_NAME="CertRenewalFailures"
SEVERITY="warn"

# Generate a webhook config pointed at the local mock receiver. On Linux we use
# host networking so the Alertmanager container can reach 127.0.0.1:18080.
# Use a dedicated Alertmanager port (19093) so this test cannot clash with a
# stack already running Alertmanager on the default 9093.
MOCK_PORT=18080
AM_PORT=19093
AM_CONFIG="$TMP/am-delivery.yml"
AM_API="http://127.0.0.1:$AM_PORT/api/v2/alerts"

# For a fast, focused delivery test we use a minimal webhook config with 1s
# grouping/interval so the firing and resolved notifications are dispatched
# immediately (the production generator intentionally batches with
# group_wait=30s / group_interval=5m, which would make this test minutes long).
cat > "$AM_CONFIG" <<EOF
route:
  group_by: ['alertname']
  group_wait: 1s
  group_interval: 1s
  repeat_interval: 5s
  receiver: 'webhook'
receivers:
  - name: 'webhook'
    webhook_configs:
      - url: 'http://127.0.0.1:$MOCK_PORT/status-list'
        send_resolved: true
EOF

# Start the mock receiver.
NOTIFICATIONS="$TMP/notifications.jsonl"
python3 "$MOCK" --port "$MOCK_PORT" --out "$NOTIFICATIONS" &
MOCK_PID=$!
sleep 1

# Start Alertmanager on the host network, bound to the dedicated AM_PORT.
# --cluster.listen-address= disables the internal gossip cluster so the alert
# dispatcher starts immediately (otherwise dispatch is delayed ~10s waiting for
# the cluster to settle, which would make this test slow and flaky).
docker run -d --name alertmanager-test --network host \
  -v "$AM_CONFIG:/etc/alertmanager/alertmanager.yml:ro" \
  --entrypoint /bin/alertmanager "$AM_IMAGE" \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --web.listen-address="127.0.0.1:$AM_PORT" \
  --cluster.listen-address= >/dev/null
sleep 3

# Fire + then resolve the alert through the Alertmanager API (host network, so
# 127.0.0.1:$AM_PORT is Alertmanager and :18080 is the mock receiver).
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

firing_payload() {
  # No endsAt -> an active (firing) alert.
  cat <<JSON
[
  {"labels":{"alertname":"$ALERT_NAME","severity":"$SEVERITY","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"certificate renewal is failing","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/cert-renewal.md"},
   "startsAt":"$NOW"}
]
JSON
}

resolved_payload() {
  # Both timestamps in the past (startsAt < endsAt) so Alertmanager treats the
  # alert as resolved and dispatches a "resolved" notification.
  cat <<JSON
[
  {"labels":{"alertname":"$ALERT_NAME","severity":"$SEVERITY","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"certificate renewal is failing","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/cert-renewal.md"},
   "startsAt":"$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)","endsAt":"$(date -u -d '1 minute ago' +%Y-%m-%dT%H:%M:%SZ)"}
]
JSON
}

curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(firing_payload)" >/dev/null
sleep 3
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(resolved_payload)" >/dev/null
sleep 3

# Stop Alertmanager, then the mock (which writes + closes the sink).
docker rm -f alertmanager-test >/dev/null 2>&1 || true
kill "$MOCK_PID" 2>/dev/null || true
wait "$MOCK_PID" 2>/dev/null || true

[ -s "$NOTIFICATIONS" ] || fail "mock receiver got no notifications"

STATUSES="$(python3 - "$NOTIFICATIONS" <<'PY'
import json, sys
statuses = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    data = json.loads(line)
    for alert in data.get("alerts", []):
        statuses.append(alert.get("status"))
print("\n".join(statuses))
PY
)"
grep -q "firing" <<<"$STATUSES" || fail "no FIRING notification delivered"
grep -q "resolved" <<<"$STATUSES" || fail "no RESOLVED notification delivered"
pass "mock webhook received both firing and resolved notifications"

echo
echo "All Alertmanager webhook tests passed."
