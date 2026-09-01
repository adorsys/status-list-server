#!/bin/sh
# Generate the Alertmanager notification receiver config from environment
# variables, so the same stack can notify ANY platform the customer chooses
# (Slack, Discord, Teams, Mattermost, email, or a generic webhook) without any
# repo changes or platform-specific code in version control.
#
# Routing (severity -> default/page/warn, repeat intervals) is static and
# platform-independent; only the `receivers:` block is generated per platform.
#
# Required env:
#   ALERTMANAGER_PLATFORM   slack|discord|teams|mattermost|email|webhook
#
# Per-platform credentials (set the ones for your chosen platform):
#   slack:      SLACK_WEBHOOK_URL  (a Slack incoming-webhook URL)
#   discord:    DISCORD_WEBHOOK_URL
#   teams:      MS_TEAMS_WEBHOOK_URL
#   mattermost: MATTERMOST_WEBHOOK_URL
#   email:      ALERTMANAGER_SMTP_HOST, ALERTMANAGER_SMTP_PORT,
#               ALERTMANAGER_EMAIL_TO, ALERTMANAGER_SMTP_FROM
#   webhook:    ALERTMANAGER_WEBHOOK_URL  (generic endpoint accepting
#               Alertmanager's standard JSON — NOT Slack/Discord/Teams, which
#               require native receivers)
#
# The three route targets (default/page/warn) share the selected platform's
# receiver; a per-channel separation is done by pointing each route at a
# different receiver only if ALERTMANAGER_*_TO overrides are provided (email).

set -eu

PLATFORM="${ALERTMANAGER_PLATFORM:-}"
OUT="${ALERTMANAGER_OUT:-/etc/alertmanager/alertmanager.yml}"

if [ -z "$PLATFORM" ]; then
  echo "ERROR: ALERTMANAGER_PLATFORM is not set (need slack|discord|teams|mattermost|email|webhook)"
  exit 1
fi

# Emit a single receiver entry for the given platform. Receives: name, then
# platform-specific vars already expanded by callers where needed.
emit_receiver() {
  _name="$1"
  case "$PLATFORM" in
    slack)
      _url="${SLACK_WEBHOOK_URL:?ALERTMANAGER: SLACK_WEBHOOK_URL required for platform=slack}"
      cat <<EOF
  - name: '$_name'
    slack_configs:
      - api_url: '$_url'
        channel: '#alerts'
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
      # MS Teams exposes a classic inbound webhook that accepts a JSON POST.
      # There is no native Alertmanager receiver for Teams in the pinned image,
      # so deliver via a generic webhook_configs (the standard Alertmanager JSON
      # payload). Most connectors that require the Adaptive Card schema can be
      # bridged by an intermediary; the JSON still carries full alert context.
      _url="${MS_TEAMS_WEBHOOK_URL:?ALERTMANAGER: MS_TEAMS_WEBHOOK_URL required for platform=teams}"
      cat <<EOF
  - name: '$_name'
    webhook_configs:
      - url: '$_url'
        send_resolved: true
EOF
      ;;
    mattermost)
      # Mattermost exposes an incoming webhook that accepts a JSON POST; there
      # is no native mattermost receiver in Alertmanager, so use a generic
      # webhook_configs pointed at the Mattermost inbound webhook.
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

# Static, platform-independent routing (plus global SMTP block for email).
{
  if [ "$PLATFORM" = "email" ]; then
    _host="${ALERTMANAGER_SMTP_HOST:?ALERTMANAGER: ALERTMANAGER_SMTP_HOST required for platform=email}"
    _port="${ALERTMANAGER_SMTP_PORT:-587}"
    _from="${ALERTMANAGER_SMTP_FROM:-alertmanager@localhost}"
    cat <<EOF
global:
  smtp_smarthost: '$_host:$_port'
  smtp_from: '$_from'
  smtp_require_tls: true

EOF
  fi
  cat <<'EOF'
# Generated from ALERTMANAGER_PLATFORM + credentials at container start.
# Routing is platform-independent; receivers are platform-specific.

route:
  group_by: ['alertname', 'sli']
  group_wait: 30s
  group_interval: 5m
  receiver: 'default'
  routes:
    - matchers:
        - severity="page"
      receiver: 'page'
      repeat_interval: 4h
    - matchers:
        - severity="warn"
      receiver: 'warn'
      repeat_interval: 24h

receivers:
EOF
} > "$OUT"

{
  emit_receiver default
  emit_receiver page
  emit_receiver warn
} >> "$OUT"

echo "ALERTMANAGER: wrote $OUT for platform=$PLATFORM"
