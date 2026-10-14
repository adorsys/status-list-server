#!/usr/bin/env bash
set -euo pipefail
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

# Extract the rendered PrometheusRule groups (the deployed rule copy).
docs = [d for d in yaml.safe_load_all(open(str(work / 'helm-render.yaml'))) if d]
cr = next(d for d in docs if d.get('kind') == 'PrometheusRule')
with open(str(work / 'helm-rules.yml'), 'w') as f:
    yaml.safe_dump({'groups': cr['spec']['groups']}, f, sort_keys=False)

# Drift guard: the deployed copy must define the same rule names as the
# standalone, promtool-tested rules EXCEPT for the one intentional
# difference — Watchdog. kube-prometheus-stack 91.4.0 already ships its own
# always-firing Watchdog, so a per-release copy would duplicate it and, with
# the optional app AlertmanagerConfig disabled in production, page the
# platform's matcher-free fallback as a normal notification. The deployed
# rule therefore omits Watchdog (StatusListMetricsAbsent covers application
# scrape health); only the standalone Docker rules retain their own
# Watchdog. Thresholds are parameterized via values, so compare names, not
# numeric values.
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

# Unit-test the deployed copy with the same alerting suite used for the
# standalone rules, adjusted for the differences introduced by the Helm
# template -- and rule_files. The deployed copy differs from the
# standalone rules in exactly these ways:
#   1. It ships NO Watchdog (see the drift-guard note above), so any
#      Watchdog expectations from the standalone suite are dropped.
#   2. Every remaining alert carries a static `namespace: ns1` label (it
#      is namespaced to the release), so StatusListMetricsAbsent
#      expectations gain `namespace: ns1`.
#   3. StatusListMetricsAbsent is based on the scrape-generated `up`
#      series selected by `service` (the rendered ServiceMonitor
#      Service), not the standalone job/target selector or the app's
#      otel_scope_name label, so its expected label set has only
#      namespace/service/static labels and its description namespaces
#      the message.
#
# Rather than maintaining a second copy of the suite for the deployed
# rules, we rewrite the fixture to match the deployed semantics: any
# standalone `up{job="status_list_server",instance="app:8000"}` input
# series becomes the deployed `up{namespace="ns1",service="status-list-server-service"}`
# selector, the Watchdog expectations are removed, and the
# StatusListMetricsAbsent expectations are normalized.
test = yaml.safe_load(open('deploy/observability/prometheus/tests/alerting.test.yml'))
test['rule_files'] = ['helm-rules.yml']
deployed_up = 'up{namespace="ns1",service="status-list-server-service"}'
standalone_up = 'up{job="status_list_server",instance="app:8000"}'
for block in test['tests']:
    for series in block.get('input_series', []):
        if isinstance(series, dict) and 'up{' in str(series.get('series', '')):
            series['series'] = series['series'].replace(
                standalone_up, deployed_up)
    # Drop the standalone Watchdog expectations: the deployed rule omits
    # Watchdog by design (kube-prometheus-stack provides the platform one).
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
            # The deployed Helm rules keep namespace context in their
            # descriptions (namespace {{ $labels.namespace }}: ...),
            # while the standalone descriptions no longer carry the
            # empty-namespace prefix. Prepend the ns1 namespace to
            # every deployed description except RedisCacheErrors, whose
            # description has no namespace prefix in either copy.
            if at['alertname'] != 'RedisCacheErrors':
                d = alert.get('exp_annotations', {}).get('description', '')
                alert['exp_annotations']['description'] = 'namespace ns1: ' + d

# Behavioral cross-namespace isolation (the reviewer-requested outcome
# test, not just substring greps). The ns1 rule copy must never consume
# ns2 series, and loss of the expected ns1 scrape target must not be
# masked by a healthy ns2 target. Feed ONLY ns2 data (firing 5xx series,
# Redis cache errors, and a healthy ns2 `up`) and assert (a) ns1 SLO
# alerts stay silent, (b) ns1's own absence still pages despite ns2
# being healthy, and (c) the ns1 RedisCacheErrors alert does not fire
# from ns2's Redis error series.
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
