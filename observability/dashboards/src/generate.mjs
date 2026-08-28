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

// A one-line timeseries panel target (unit + a single threshold at `warnAt`).
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
    targets: [{ expr, legendFormat: legend, refId: "A" }],
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
  panels: [
    timeseries("Request latency P95", "sli:request_latency:p95:5m", "p95", "s", sloThresholds.request_latency_p95_seconds, 0, 0),
    timeseries("Error rate", "sli:error_rate:5m", "5xx ratio", "percentunit", sloThresholds.error_rate_target_ratio, 12, 0),
    {
      title: "Error budget remaining (30d)",
      type: "stat",
      datasource: { type: "prometheus", uid: "prometheus" },
      gridPos: { h: 4, w: 12, x: 0, y: 8 },
      fieldConfig: {
        defaults: thresholds(
          [
            { color: "green", value: null },
            { color: "red", value: 0 },
          ],
          "percentunit"
        ),
      },
      targets: [{ expr: "sli:error_budget:success:30d", refId: "A" }],
    },
    {
      title: "Token-gen error budget (30d)",
      type: "stat",
      datasource: { type: "prometheus", uid: "prometheus" },
      gridPos: { h: 4, w: 12, x: 12, y: 8 },
      fieldConfig: {
        defaults: thresholds(
          [
            { color: "green", value: null },
            { color: "red", value: 0 },
          ],
          "percentunit"
        ),
      },
      targets: [{ expr: "sli:token_gen_error_budget:30d", refId: "A" }],
    },
    timeseries("Cache hit ratio", "sli:cache_hit_ratio:5m", "hit ratio", "percentunit", sloThresholds.cache_hit_ratio_min, 0, 12),
    timeseries("DB query latency P95", "sli:db_query_latency:p95:5m", "p95", "s", sloThresholds.db_query_latency_p95_seconds, 12, 12),
    timeseries("Cert renewal failure rate", "sli:cert_renewal_failure_rate:5m", "failure rate", "percentunit", sloThresholds.cert_renewal_failure_rate_max, 0, 20),
    timeseries("Token generation failure rate", "sli:token_gen_failure_rate:5m", "failure rate", "percentunit", sloThresholds.token_gen_failure_rate_max, 12, 20),
  ],
};

const outDir = join(here, "..", "generated");
const outFile = join(outDir, "status-list-slo.json");
mkdirSync(outDir, { recursive: true });
writeFileSync(outFile, `${JSON.stringify(dashboard, null, 2)}\n`);
console.log(`Wrote ${outFile}`);
