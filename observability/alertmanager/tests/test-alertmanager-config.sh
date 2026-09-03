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
# Portability note:
#   Step [2/2] uses `--network host` so the containerized Alertmanager can POST
#   to mock Python servers listening on 127.0.0.1. `--network host` requires a
#   Linux execution environment (standard for CI and Linux developer machines).
#
# Run from the repository root:
#   observability/alertmanager/tests/test-alertmanager-config.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GENERATOR="$REPO_ROOT/observability/prometheus/generate-alertmanager-config.sh"
MOCK="$REPO_ROOT/observability/alertmanager/tests/mock_webhook.py"
AM_IMAGE="prom/alertmanager:v0.28.1"
TMP="$(mktemp -d)"
HUMAN_PID=""
DMS_PID=""
cleanup() {
  docker rm -f alertmanager-test >/dev/null 2>&1 || true
  [ -n "${HUMAN_PID:-}" ] && kill "$HUMAN_PID" 2>/dev/null || true
  [ -n "${DMS_PID:-}" ] && kill "$DMS_PID" 2>/dev/null || true
  [ -n "${HUMAN_PID:-}" ] && wait "$HUMAN_PID" 2>/dev/null || true
  [ -n "${DMS_PID:-}" ] && wait "$DMS_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

# Portable "N minutes ago" RFC3339 timestamp: GNU date -> BSD date -> python.
ts_past_iso() {
  local mins="$1"
  if date -u -d "$mins minutes ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; then
    return 0
  fi
  if date -u -v -"${mins}M" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; then
    return 0
  fi
  python3 -c 'import datetime, sys; print((datetime.datetime.utcnow()-datetime.timedelta(minutes=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$mins"
}

# Poll a receiver's notification log until an alert with the given alertname
# (and optional status) is seen. Returns 0 on match, 1 on timeout.
wait_for_alert() {
  local log="$1" name="$2" status="${3:-}" timeout="${4:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    if python3 - "$log" "$name" "$status" <<'PY'
import json, sys, os
log, name, status = sys.argv[1], sys.argv[2], sys.argv[3] or None
if not os.path.exists(log):
    sys.exit(1)
for line in open(log):
    line = line.strip()
    if not line:
        continue
    for alert in json.loads(line).get("alerts", []):
        if alert.get("labels", {}).get("alertname") == name:
            if status is None or alert.get("status") == status:
                sys.exit(0)
sys.exit(1)
PY
    then
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  return 1
}

# Assert an alertname is ABSENT from a receiver's log (routing-gap guard).
assert_absent() {
  local log="$1" name="$2"
  sleep 2
  if python3 - "$log" "$name" <<'PY'
import json, sys, os
log, name = sys.argv[1], sys.argv[2]
if not os.path.exists(log):
    sys.exit(1)
for line in open(log):
    line = line.strip()
    if not line:
        continue
    for alert in json.loads(line).get("alerts", []):
        if alert.get("labels", {}).get("alertname") == name:
            sys.exit(0)
sys.exit(1)
PY
  then
    return 1
  fi
  return 0
}

echo "[1/2] Config generation is valid for every platform"
for PLATFORM in webhook discord slack teams mattermost email; do
  OUT="$TMP/am-$PLATFORM.yml"
  case "$PLATFORM" in
    webhook)    CREDS=(ALERTMANAGER_WEBHOOK_URL=https://hooks.example.com/status-list) ;;
    discord)    CREDS=(DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/000/aaa) ;;
    slack)      CREDS=(SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TTT/BBB/SSS) ;;
    teams)      CREDS=(MS_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/000/aaa) ;;
    mattermost) CREDS=(MATTERMOST_WEBHOOK_URL=https://mm.example.com/hooks/aaa) ;;
    email)      CREDS=(ALERTMANAGER_SMTP_HOST=smtp.example.com ALERTMANAGER_EMAIL_TO=ops@example.com ALERTMANAGER_SMTP_FROM=alerts@example.com) ;;
  esac
  env ALERTMANAGER_PLATFORM="$PLATFORM" ALERTMANAGER_OUT="$OUT" \
    "${CREDS[@]}" /bin/sh "$GENERATOR" >/dev/null \
      || fail "$PLATFORM: generator exited non-zero"
  docker run --rm -v "$OUT:/etc/alertmanager/alertmanager.yml:ro" \
    --entrypoint amtool "$AM_IMAGE" check-config /etc/alertmanager/alertmanager.yml \
    >/dev/null 2>&1 || fail "$PLATFORM: amtool rejected generated config"
  pass "$PLATFORM"
done

echo "[2/2] Alert delivery (firing + resolved + routing) using the GENERATED config"
# This section boots a real Alertmanager with the config produced by
# generate-alertmanager-config.sh (not a hand-written minimal config), so the
# real routing — single human channel for page/warn + a separate dead-man's
# switch for the severity=none Watchdog — is exercised and asserted.

# The production generator batches with group_wait=30s / group_interval=5m,
# which would make this test minutes long, so we override the intervals to 1s;
# every other aspect (routing, receivers, inhibit_rules) is exactly what ships.
HUMAN_PORT=18080
DMS_PORT=18081
AM_PORT=19093
AM_CONFIG="$TMP/am-delivery.yml"
AM_API="http://127.0.0.1:$AM_PORT/api/v2/alerts"
HUMAN_LOG="$TMP/human.jsonl"
DMS_LOG="$TMP/dms.jsonl"

env ALERTMANAGER_PLATFORM=webhook \
  ALERTMANAGER_WEBHOOK_URL="http://127.0.0.1:$HUMAN_PORT/status-list" \
  ALERTMANAGER_DMS_WEBHOOK_URL="http://127.0.0.1:$DMS_PORT/ping" \
  ALERTMANAGER_GROUP_WAIT=1s ALERTMANAGER_GROUP_INTERVAL=1s \
  ALERTMANAGER_OUT="$AM_CONFIG" /bin/sh "$GENERATOR" >/dev/null \
  || fail "generator failed to emit delivery config"

# Two mock receivers: one where page/warn alerts land, one where the Watchdog
# dead-man's-switch pings. On Linux host networking lets the Alertmanager
# container reach 127.0.0.1 on both ports.
python3 "$MOCK" --port "$HUMAN_PORT" --out "$HUMAN_LOG" &
HUMAN_PID=$!
python3 "$MOCK" --port "$DMS_PORT" --out "$DMS_LOG" &
DMS_PID=$!
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
AM_UP=false
for _ in $(seq 1 30); do
  if curl -fsS "$AM_API" >/dev/null 2>&1; then AM_UP=true; break; fi
  sleep 1
done
[ "$AM_UP" = true ] || fail "Alertmanager API did not come up in time"

# Fire + resolve a page/warn alert, and fire the always-on Watchdog, through the
# Alertmanager API so the real routing is asserted on both receivers.
WARN_NAME="CertRenewalFailures"
SEVERITY="warn"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

firing_payload() {
  # No endsAt -> an active (firing) alert.
  cat <<JSON
[
  {"labels":{"alertname":"$1","severity":"$2","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"$1","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/cert-renewal.md"},
   "startsAt":"$NOW"}
]
JSON
}

resolved_payload() {
  # Both timestamps in the past (startsAt < endsAt) so Alertmanager treats the
  # alert as resolved and dispatches a "resolved" notification.
  cat <<JSON
[
  {"labels":{"alertname":"$1","severity":"$2","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"$1","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/observability/runbooks/cert-renewal.md"},
   "startsAt":"$(ts_past_iso 5)","endsAt":"$(ts_past_iso 1)"}
]
JSON
}

# 1. A warn alert must reach the HUMAN channel, firing then resolved.
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(firing_payload "$WARN_NAME" "$SEVERITY")" >/dev/null
wait_for_alert "$HUMAN_LOG" "$WARN_NAME" "firing" || fail "warn alert did not reach the human channel (firing)"
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(resolved_payload "$WARN_NAME" "$SEVERITY")" >/dev/null
wait_for_alert "$HUMAN_LOG" "$WARN_NAME" "resolved" || fail "warn alert did not reach the human channel (resolved)"

# 2. The Watchdog (severity=none) must go to the dead-man's-switch, NOT the
#    human channel — this is the routing that was previously broken.
WATCHDOG="Watchdog"
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(firing_payload "$WATCHDOG" "none")" >/dev/null
wait_for_alert "$DMS_LOG" "$WATCHDOG" "firing" || fail "Watchdog did not reach the dead-man's-switch"
assert_absent "$HUMAN_LOG" "$WATCHDOG" || fail "Watchdog leaked into the human channel"

pass "generated config: warn->human (firing+resolved), watchdog->dead-man's-switch (not human)"

# Stop Alertmanager, then the mocks (which write + close their sinks).
docker rm -f alertmanager-test >/dev/null 2>&1 || true
if [ -n "${HUMAN_PID:-}" ]; then
  kill "$HUMAN_PID" 2>/dev/null || true
  wait "$HUMAN_PID" 2>/dev/null || true
  HUMAN_PID=""
fi
if [ -n "${DMS_PID:-}" ]; then
  kill "$DMS_PID" 2>/dev/null || true
  wait "$DMS_PID" 2>/dev/null || true
  DMS_PID=""
fi

echo
echo "All Alertmanager webhook tests passed."
