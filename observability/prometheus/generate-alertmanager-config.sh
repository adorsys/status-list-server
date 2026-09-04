#!/bin/sh
# Generate the Alertmanager notification receiver config from environment
# variables, so the same stack can notify ANY platform the customer chooses
# (Slack, Discord, Teams, Mattermost, email, or a generic webhook) without any
# repo changes or platform-specific code in version control.
#
# Routing (severity -> human / dead-man's-switch / noop, repeat intervals) is
# static and platform-independent; only the human-channel `receivers:` block is
# generated per platform. Alerts are channelled into a SINGLE human receiver:
# All human alerts route to a single receiver carrying the severity label in the payload,
# matching the platform credential model where one destination endpoint is configured.
#
# Required env:
#   ALERTMANAGER_PLATFORM   slack|discord|teams|mattermost|email|webhook
#
# Per-platform credentials (set the one for your chosen platform):
#   slack:      SLACK_WEBHOOK_URL  (a Slack incoming-webhook URL),
#               SLACK_CHANNEL      (optional channel override, e.g. #alerts)
#   discord:    DISCORD_WEBHOOK_URL
#   teams:      MS_TEAMS_WEBHOOK_URL
#   mattermost: MATTERMOST_WEBHOOK_URL
#   email:      ALERTMANAGER_SMTP_HOST, ALERTMANAGER_SMTP_PORT,
#               ALERTMANAGER_EMAIL_TO, ALERTMANAGER_SMTP_FROM
#   webhook:    ALERTMANAGER_WEBHOOK_URL  (generic endpoint accepting
#               Alertmanager's standard JSON — NOT Slack/Discord/Teams, which
#               require native receivers)
#
# Optional:
#   ALERTMANAGER_DMS_WEBHOOK_URL  dead-man's-switch webhook (e.g. a hosted
#               Dead Man's Snitch / Healthchecks.io ping URL). The always-firing
#               Watchdog (severity=none) routes here so a total collapse of
#               Prometheus/Alertmanager is detected by its ABSENCE. When this is
#               not set the watchdog is absorbed by an empty receiver so it never
#               spams the human channel and never re-notifies on every interval.

set -eu

PLATFORM="${ALERTMANAGER_PLATFORM:-}"
OUT="${ALERTMANAGER_OUT:-/etc/alertmanager/alertmanager.yml}"
# Grouping / dispatch intervals. Production defaults batch notifications to
# avoid channel spam; the delivery test overrides them to run in seconds.
GROUP_WAIT="${ALERTMANAGER_GROUP_WAIT:-30s}"
GROUP_INTERVAL="${ALERTMANAGER_GROUP_INTERVAL:-5m}"

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
    _from="${ALERTMANAGER_SMTP_FROM:?ALERTMANAGER: ALERTMANAGER_SMTP_FROM required for platform=email}"
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
EOF
  printf "  group_wait: %s\n  group_interval: %s\n" "$GROUP_WAIT" "$GROUP_INTERVAL"
  cat <<'EOF'
  # Anything not explicitly routed (no severity, or an unknown one) is absorbed
  # by the noop sink so it never spams a human channel. The always-firing
  # Watchdog (severity=none) is routed to the dead-man's-switch below, so its
  # ABSENCE is what pages a human, not its firing.
  receiver: 'noop'
  routes:
    # Watchdog (severity=none) -> dead-man's-switch (detects collapsed pipeline
    # by ABSENCE). If ALERTMANAGER_DMS_WEBHOOK_URL is unset, `deadmansswitch`
    # is an empty receiver and the watchdog is silently absorbed here.
    - matchers:
        - severity="none"
      receiver: 'deadmansswitch'

    # Page (act now) and warn (act this week) share ONE human channel; the
    # severity label is still in the payload so it can be filtered in-channel.
    - matchers:
        - severity="page"
      receiver: 'human'
      repeat_interval: 4h
    - matchers:
        - severity="warn"
      receiver: 'human'
      repeat_interval: 24h

inhibit_rules:
  # Don't let a warn for an SLI+service reach the channel while the correlated
  # page for the same SLI+service is already firing (fast-burn page + slow-burn
  # warn pairs are deliberately emitted together by the alert rules).
  - source_match:
      severity: page
    target_match:
      severity: warn
    equal: ['sli', 'service']

receivers:
  # Absorbs anything not explicitly routed.
  - name: 'noop'

  # Dead-man's-switch for the always-firing Watchdog (pages on absence, not on
  # firing). Empty (acts as a noop) when ALERTMANAGER_DMS_WEBHOOK_URL is unset.
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
