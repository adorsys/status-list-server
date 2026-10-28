#!/bin/sh
# Builds alertmanager.yml from env, so any platform works without code changes.
# ALERTMANAGER_PLATFORM: slack|discord|teams|mattermost|email|webhook, plus that platform's URL or SMTP vars.
# ALERTMANAGER_DMS_WEBHOOK_URL (optional) receives the always-firing Watchdog.

set -eu

PLATFORM="${ALERTMANAGER_PLATFORM:-}"
OUT="${ALERTMANAGER_OUT:-/etc/alertmanager/alertmanager.yml}"
# The delivery test shortens these.
GROUP_WAIT="${ALERTMANAGER_GROUP_WAIT:-30s}"
GROUP_INTERVAL="${ALERTMANAGER_GROUP_INTERVAL:-5m}"

if [ -z "$PLATFORM" ]; then
  echo "ERROR: ALERTMANAGER_PLATFORM is not set (need slack|discord|teams|mattermost|email|webhook)"
  exit 1
fi

emit_receiver() {
  _name="$1"
  case "$PLATFORM" in
    slack)
      _url="${SLACK_WEBHOOK_URL:?ALERTMANAGER: SLACK_WEBHOOK_URL required for platform=slack}"
      _channel="${SLACK_CHANNEL:-}"
      cat <<EOF
  - name: '$_name'
    slack_configs:
      - api_url: '$_url'
EOF
      if [ -n "$_channel" ]; then
        cat <<EOF
        channel: '$_channel'
EOF
      fi
      cat <<EOF
        send_resolved: true
        title: '{{ template "slack.default.title" . }}'
        text: '{{ template "slack.default.text" . }}'
EOF
      ;;
    discord)
      _url="${DISCORD_WEBHOOK_URL:?ALERTMANAGER: DISCORD_WEBHOOK_URL required for platform=discord}"
      cat <<EOF
  - name: '$_name'
    discord_configs:
      - webhook_url: '$_url'
        send_resolved: true
        title: '{{ template "discord.default.title" . }}'
        message: '{{ template "discord.default.message" . }}'
EOF
      ;;
    teams)
      # No native Teams receiver in the pinned image, so send the generic JSON.
      _url="${MS_TEAMS_WEBHOOK_URL:?ALERTMANAGER: MS_TEAMS_WEBHOOK_URL required for platform=teams}"
      cat <<EOF
  - name: '$_name'
    webhook_configs:
      - url: '$_url'
        send_resolved: true
EOF
      ;;
    mattermost)
      # No native Mattermost receiver; use the generic webhook.
      _url="${MATTERMOST_WEBHOOK_URL:?ALERTMANAGER: MATTERMOST_WEBHOOK_URL required for platform=mattermost}"
      cat <<EOF
  - name: '$_name'
    webhook_configs:
      - url: '$_url'
        send_resolved: true
EOF
      ;;
    email)
      _to="${ALERTMANAGER_EMAIL_TO:?ALERTMANAGER: ALERTMANAGER_EMAIL_TO required for platform=email}"
      cat <<EOF
  - name: '$_name'
    email_configs:
      - to: '$_to'
        send_resolved: true
        html: '{{ template "email.default.html" . }}'
EOF
      ;;
    webhook)
      _url="${ALERTMANAGER_WEBHOOK_URL:?ALERTMANAGER: ALERTMANAGER_WEBHOOK_URL required for platform=webhook}"
      cat <<EOF
  - name: '$_name'
    webhook_configs:
      - url: '$_url'
        send_resolved: true
EOF
      ;;
    *)
      echo "ERROR: unsupported ALERTMANAGER_PLATFORM '$PLATFORM' (support: slack|discord|teams|mattermost|email|webhook)" >&2
      exit 1
      ;;
  esac
}

{
  if [ "$PLATFORM" = "email" ]; then
    _host="${ALERTMANAGER_SMTP_HOST:?ALERTMANAGER: ALERTMANAGER_SMTP_HOST required for platform=email}"
    _port="${ALERTMANAGER_SMTP_PORT:-587}"
    _from="${ALERTMANAGER_SMTP_FROM:?ALERTMANAGER: ALERTMANAGER_SMTP_FROM required for platform=email}"
    cat <<EOF
global:
  smtp_smarthost: '$_host:$_port'
  smtp_from: '$_from'
  smtp_require_tls: true

EOF
  fi
  cat <<'EOF'
# Generated at container start from ALERTMANAGER_PLATFORM; don't edit by hand.

route:
  group_by: ['alertname', 'sli', 'service']
EOF
  printf "  group_wait: %s\n  group_interval: %s\n" "$GROUP_WAIT" "$GROUP_INTERVAL"
  cat <<'EOF'
  # Unrouted alerts go to noop, never to a human.
  receiver: 'noop'
  routes:
    # Watchdog goes to the dead man's switch, or nowhere if none is set.
    - matchers:
        - severity="none"
      receiver: 'deadmansswitch'

    # page and warn share one channel; filter on the severity label.
    - matchers:
        - severity="page"
      receiver: 'human'
      repeat_interval: 4h
    - matchers:
        - severity="warn"
      receiver: 'human'
      repeat_interval: 24h

inhibit_rules:
  # A firing page mutes the matching warn.
  - source_match:
      severity: page
    target_match:
      severity: warn
    equal: ['sli', 'service']

receivers:
  - name: 'noop'

  - name: 'deadmansswitch'
EOF

  if [ -n "${ALERTMANAGER_DMS_WEBHOOK_URL:-}" ]; then
    cat <<EOF
    webhook_configs:
      - url: '$ALERTMANAGER_DMS_WEBHOOK_URL'
        send_resolved: false
EOF
  fi
} > "$OUT"

{
  emit_receiver human
} >> "$OUT"

echo "ALERTMANAGER: wrote $OUT for platform=$PLATFORM"
