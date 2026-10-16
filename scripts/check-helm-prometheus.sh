#!/usr/bin/env bash
set -euo pipefail

# Adds a test-only audience: the chart has no default, so deployments must choose one.
helm() {
  local action="$1"
  shift
  if [[ "$action" == template || "$action" == lint ]]; then
    command helm "$action" --set-string statuslist.env.APP_MANAGEMENT_AUTH__AUDIENCES=https://helm-ci.invalid/api/v1 "$@"
  else
    command helm "$action" "$@"
  fi
}
CHART_DIR="${CHART_DIR:-deploy/helm/chart}"
export CHECK_TEMP
CHECK_TEMP=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/helm-prometheus.XXXXXX")
trap 'rm -rf "$CHECK_TEMP"' EXIT
helm template status-list-server "$CHART_DIR" \
  --namespace ns1 \
  --set prometheusRule.enabled=true > "$CHECK_TEMP/helm-render.yaml"
python3 - <<'EOF'
import os, subprocess, yaml
from pathlib import Path
work = Path(os.environ['CHECK_TEMP'])

docs = [d for d in yaml.safe_load_all(open(str(work / 'helm-render.yaml'))) if d]
cr = next(d for d in docs if d.get('kind') == 'PrometheusRule')
with open(str(work / 'helm-rules.yml'), 'w') as f:
    yaml.safe_dump({'groups': cr['spec']['groups']}, f, sort_keys=False)

# Same rule names as the standalone set, minus Watchdog (kube-prometheus-stack ships its own).
def rule_names(path):
    rules = yaml.safe_load(open(path))['groups']
    names = set()
    for g in rules:
        for r in g['rules']:
            names.add(r.get('record') or r.get('alert'))
    return names
standalone = rule_names('deploy/observability/prometheus/rules/recording.rules.yml') | rule_names('deploy/observability/prometheus/rules/alerting.rules.yml')
deployed = rule_names(str(work / 'helm-rules.yml'))
expected = standalone - {'Watchdog'}
if deployed != expected:
    raise SystemExit(
        f"DRIFT: deployed PrometheusRule rule names differ from the tested standalone rules.\n"
        f"  expected (standalone minus the intentional Watchdog omission): {sorted(expected)}\n"
        f"  only in standalone: {sorted(standalone - deployed)}\n"
        f"  only in deployed:   {sorted(deployed - standalone)}"
    )

# Reuse the standalone promtool suite, rewritten for the deployed copy:
# no Watchdog, a namespace: ns1 label, and up selected by service instead of job/instance.
test = yaml.safe_load(open('deploy/observability/prometheus/tests/alerting.test.yml'))
test['rule_files'] = ['helm-rules.yml']
deployed_up = 'up{namespace="ns1",service="status-list-server-service"}'
standalone_up = 'up{job="status_list_server",instance="app:8000"}'
for block in test['tests']:
    for series in block.get('input_series', []):
        if isinstance(series, dict) and 'up{' in str(series.get('series', '')):
            series['series'] = series['series'].replace(
                standalone_up, deployed_up)
    block['alert_rule_test'] = [
        at for at in block.get('alert_rule_test', [])
        if at.get('alertname') != 'Watchdog'
    ]
    for at in block.get('alert_rule_test', []):
        for alert in at.get('exp_alerts', []):
            if at['alertname'] == 'StatusListMetricsAbsent':
                alert['exp_labels'].pop('job', None)
                alert['exp_labels'].pop('instance', None)
                alert['exp_labels'].pop('otel_scope_name', None)
                alert['exp_labels']['namespace'] = 'ns1'
            # Deployed descriptions start with the namespace, except RedisCacheErrors.
            if at['alertname'] != 'RedisCacheErrors':
                d = alert.get('exp_annotations', {}).get('description', '')
                alert['exp_annotations']['description'] = 'namespace ns1: ' + d

# Feed only ns2 data: ns1 alerts must stay silent, and ns1's own absence must still page.
ns2_up = 'up{namespace="ns2",service="status-list-server-service"}'
test['tests'].append({
    'interval': '1m',
    'input_series': [
        {'series': 'http_server_requests_total{otel_scope_name="status-list-server",namespace="ns2",method="GET",route="/x",status_class="5xx"}',
         'values': '0+100x400'},
        {'series': 'http_server_requests_total{otel_scope_name="status-list-server",namespace="ns2",method="GET",route="/x",status_class="2xx"}',
         'values': '0+900x400'},
        {'series': 'status_list_cache_errors_total{otel_scope_name="status-list-server",namespace="ns2",cache="status_list",backend="redis",operation="get"}',
         'values': '0+60x10'},
        {'series': ns2_up, 'values': '1x410'},
    ],
    'alert_rule_test': [
        {'eval_time': '400m', 'alertname': 'ErrorRateFastBurn',
         'exp_alerts': []},
        {'eval_time': '400m', 'alertname': 'ErrorRateSlowBurn',
         'exp_alerts': []},
        {'eval_time': '10m', 'alertname': 'RedisCacheErrors',
         'exp_alerts': []},
        {'eval_time': '10m', 'alertname': 'StatusListMetricsAbsent',
         'exp_alerts': [{'exp_labels': {
                         'service': 'status-list-server',
                         'severity': 'page',
                         'team': 'statuslist',
                         'namespace': 'ns1'},
                         'exp_annotations': {
                         'summary': 'status-list-server metrics absent for 5m (target down or not scraped)',
                         'description': 'namespace ns1: Status List /metrics target is unreachable or absent (up == 0 or no up series for 5m)',
                         'runbook_url': 'https://github.com/adorsys/status-list-server/blob/develop/deploy/observability/README.md',
                         'dashboard_url': 'http://localhost:3000/d/status-list-slo'}}]},
    ],
})
with open(str(work / 'helm-alerting.test.yml'), 'w') as f:
    yaml.safe_dump(test, f, sort_keys=False)
EOF
docker run --rm -w /tmp \
  -v "$CHECK_TEMP/helm-rules.yml":/tmp/helm-rules.yml:ro \
  -v "$CHECK_TEMP/helm-alerting.test.yml":/tmp/helm-alerting.test.yml:ro \
  --entrypoint promtool \
  prom/prometheus:v3.11.3@sha256:e4254400b85610324913f0dc4acf92603d9984e7519414c5a12811aa6146acc3 test rules /tmp/helm-alerting.test.yml
