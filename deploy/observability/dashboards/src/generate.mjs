// Deterministic generator for the Status List SLO dashboard.
//
// Run `npm run generate-dashboards` (in this directory) to regenerate
// `../generated/status-list-slo.json`. The output is byte-for-byte stable
// (JSON.stringify with 2-space indent), so a changed intent shows up as a
// reviewable diff in the committed JSON.
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sloThresholds = JSON.parse(
  readFileSync(join(here, "../../slo/thresholds.json"), "utf8")
);

const thresholds = (steps, unit) => ({ unit, thresholds: { mode: "absolute", steps } });

// Namespace isolation. This dashboard is published to a cluster-wide Grafana,
// and the recording series retain the `namespace` label, so multiple Status
// List releases must never be mixed into the same panel. Every query is
// therefore routed through the `$namespace` template variable (a
// Prometheus-backed dashboard variable) and every legend carries {{namespace}}.
const NAMESPACE_MATCHER = '{namespace=~"$namespace"}';
const scoped = (expr) => `${expr}${NAMESPACE_MATCHER}`;

// A one-line timeseries panel target. `warnAt` is the value at which the panel
// turns red; values below stay green. Use this for "higher = worse" metrics
// (latency, error/failure rates). For "higher = better" metrics use
// `timeseriesInverted`, which turns red when the value drops `below`.
function timeseries(title, expr, legend, unit, warnAt, x, y, w = 12, h = 8) {
  return {
    title,
    type: "timeseries",
    datasource: { type: "prometheus", uid: "prometheus" },
    gridPos: { h, w, x, y },
    fieldConfig: {
      defaults: thresholds(
        [
          { color: "green", value: null },
          { color: "red", value: warnAt },
        ],
        unit
      ),
    },
    targets: [{ expr: scoped(expr), legendFormat: `{{namespace}} ${legend}`, refId: "A" }],
  };
}

// "Higher = better" timeseries: green while the value is at/above `minOk`,
// red when it drops below.
function timeseriesInverted(title, expr, legend, unit, minOk, x, y, w = 12, h = 8) {
  return {
    title,
    type: "timeseries",
    datasource: { type: "prometheus", uid: "prometheus" },
    gridPos: { h, w, x, y },
    fieldConfig: {
      defaults: thresholds(
        [
          { color: "red", value: null },
          { color: "green", value: minOk },
        ],
        unit
      ),
    },
    targets: [{ expr: scoped(expr), legendFormat: `{{namespace}} ${legend}`, refId: "A" }],
  };
}

// Stat panels (no legendFormat expected for a single scalar, but the query is
// still namespace-scoped so it cannot pick up a sibling release).
function stat(title, expr, x, y) {
  return {
    title,
    type: "stat",
    datasource: { type: "prometheus", uid: "prometheus" },
    gridPos: { h: 4, w: 12, x, y },
    fieldConfig: {
      defaults: thresholds(
        [
          { color: "red", value: null },
          { color: "green", value: 0.1 },
        ],
        "percentunit"
      ),
    },
    targets: [{ expr: scoped(expr), refId: "A" }],
  };
}

const dashboard = {
  title: "Status List SLO",
  uid: process.env.GRAFANA_DASHBOARD_UID || "status-list-slo",
  version: 1,

  schemaVersion: 39,
  tags: ["status-list", "slo"],
  timezone: "utc",
  refresh: "15s",
  time: { from: "now-1h", to: "now" },
  templating: {
    list: [
      {
        name: "namespace",
        type: "query",
        datasource: { type: "prometheus", uid: "prometheus" },
        definition: "label_values(sli:request_latency:p95:5m, namespace)",
        query: {
          query: "label_values(sli:request_latency:p95:5m, namespace)",
          refId: "namespace-variable",
        },
        refresh: 1,
        includeAll: true,
        allValue: ".*",
        multi: false,
        label: "Namespace",
        hide: 0,
      },
    ],
  },
  panels: [
    timeseries("Request latency P95", "sli:request_latency:p95:5m", "p95", "s", sloThresholds.request_latency_p95_seconds, 0, 0),
    timeseries("Error rate", "sli:error_rate:5m", "5xx ratio", "percentunit", sloThresholds.error_rate_target_ratio, 12, 0),
    stat("Error budget remaining (30d)", "sli:error_budget:success:30d", 0, 8),
    stat("Token-gen error budget (30d)", "sli:token_gen_error_budget:30d", 12, 8),
    timeseriesInverted("Cache hit ratio", "sli:cache_hit_ratio:5m", "hit ratio", "percentunit", sloThresholds.cache_hit_ratio_min, 0, 12),
    timeseries("DB query latency P95", "sli:db_query_latency:p95:5m", "p95", "s", sloThresholds.db_query_latency_p95_seconds, 12, 12),
    timeseries("Cert renewal failure rate", "sli:cert_renewal_failure_rate:5m", "failure rate", "percentunit", sloThresholds.cert_renewal_failure_rate_max, 0, 20),
    timeseries("Token generation failure rate", "sli:token_gen_failure_rate:5m", "failure rate", "percentunit", sloThresholds.token_gen_failure_rate_max, 12, 20),
  ],
};

// Write the canonical artifact AND the chart-local copy the Helm chart embeds
// via .Files.Get. Keeping both in one generator run means a dashboard update
// cannot land while the deployed ConfigMap drifts — CI diffs both byte-for-byte.
const outDir = join(here, "..", "generated");
const outFile = join(outDir, "status-list-slo.json");
const json = `${JSON.stringify(dashboard, null, 2)}\n`;

const chartCopyRel = "../../../helm/chart/observability/dashboards/generated";
const chartCopyFile = join(here, chartCopyRel, "status-list-slo.json");
mkdirSync(join(here, chartCopyRel), { recursive: true });
writeFileSync(outFile, json);
writeFileSync(chartCopyFile, json);
console.log(`Wrote ${outFile}`);
console.log(`Wrote ${chartCopyFile}`);
