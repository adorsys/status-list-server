#!/usr/bin/env bash
# Checks the generated config for every platform, then real delivery through Alertmanager.
# Needs docker and python3; step 2 uses --network host, so Linux only. Run from the repo root.
set -euo pipefail

REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
GENERATOR="$REPO_ROOT/deploy/observability/prometheus/generate-alertmanager-config.sh"
MOCK="$REPO_ROOT/deploy/observability/alertmanager/tests/mock_webhook.py"
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

python3 "$MOCK" --port "$HUMAN_PORT" --out "$HUMAN_LOG" &
HUMAN_PID=$!
python3 "$MOCK" --port "$DMS_PORT" --out "$DMS_LOG" &
DMS_PID=$!
sleep 1

# An empty --cluster.listen-address skips gossip, which would delay dispatch by ~10s.
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

WARN_NAME="CertRenewalFailures"
SEVERITY="warn"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

firing_payload() {
  cat <<JSON
[
  {"labels":{"alertname":"$1","severity":"$2","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"$1","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/deploy/observability/runbooks/cert-renewal.md"},
   "startsAt":"$NOW"}
]
JSON
}

resolved_payload() {
  cat <<JSON
[
  {"labels":{"alertname":"$1","severity":"$2","service":"status-list-server","sli":"cert_renewal"},
   "annotations":{"summary":"$1","runbook_url":"https://github.com/adorsys/status-list-server/blob/develop/deploy/observability/runbooks/cert-renewal.md"},
   "startsAt":"$(ts_past_iso 5)","endsAt":"$(ts_past_iso 1)"}
]
JSON
}

curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(firing_payload "$WARN_NAME" "$SEVERITY")" >/dev/null
wait_for_alert "$HUMAN_LOG" "$WARN_NAME" "firing" || fail "warn alert did not reach the human channel (firing)"
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(resolved_payload "$WARN_NAME" "$SEVERITY")" >/dev/null
wait_for_alert "$HUMAN_LOG" "$WARN_NAME" "resolved" || fail "warn alert did not reach the human channel (resolved)"

WATCHDOG="Watchdog"
curl -fsS -X POST "$AM_API" -H 'Content-Type: application/json' -d "$(firing_payload "$WATCHDOG" "none")" >/dev/null
wait_for_alert "$DMS_LOG" "$WATCHDOG" "firing" || fail "Watchdog did not reach the dead-man's-switch"
assert_absent "$HUMAN_LOG" "$WATCHDOG" || fail "Watchdog leaked into the human channel"

pass "generated config: warn->human (firing+resolved), watchdog->dead-man's-switch (not human)"

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
