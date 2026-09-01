import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const thresholds = JSON.parse(
  readFileSync(join(here, "thresholds.json"), "utf8")
);

const alertingRules = readFileSync(join(here, "../prometheus/rules/alerting.rules.yml"), "utf8");
const recordingRules = readFileSync(join(here, "../prometheus/rules/recording.rules.yml"), "utf8");
const readme = readFileSync(join(here, "README.md"), "utf8");
const helmValues = readFileSync(join(here, "../../helm/chart/values.yaml"), "utf8");

let errors = [];

function checkMatch(content, filename, pattern, description) {
  if (!pattern.test(content)) {
    errors.push(`[${filename}] Expected ${description} matching ${pattern}`);
  }
}

// Parse the scalar `slo:` block in helm/chart/values.yaml into { key: number }.
// The block is a flat, 2-space-indented set of `key: <number>` lines, so this
// avoids pulling a YAML parser into the lint (the CI step has no npm deps).
function parseHelmSlo() {
  const match = helmValues.match(/^\s*slo:\s*\n([\s\S]*?)(?=\n\S|\n\z)/m);
  if (!match) return {};
  const out = {};
  for (const line of match[1].split("\n")) {
    const m = line.match(/^\s{2}([A-Za-z_][A-Za-z0-9_]*):\s*([0-9]*\.?[0-9]+)\s*$/);
    if (m) out[m[1]] = parseFloat(m[2]);
  }
  return out;
}

const helmSlo = parseHelmSlo();

// The Helm chart's configurable SLO targets are a second consumer of the same
// source of truth (thresholds.json). Assert the values.yaml `slo.*` defaults
// stay in lockstep so a Helm deployment cannot diverge from the standalone
// Prometheus always-on stack.
const helmSloMap = {
  errorRateTarget: "error_rate_target_ratio",
  fastBurnMultiplier: "fast_burn_multiplier",
  slowBurnMultiplier: "slow_burn_multiplier",
  requestLatencyP95: "request_latency_p95_seconds",
  dbLatencyP95: "db_query_latency_p95_seconds",
  cacheHitRatioMin: "cache_hit_ratio_min",
  certRenewalFailureMax: "cert_renewal_failure_rate_max",
  errorBudgetCriticalThreshold: "error_budget_critical_threshold",
  certExpiryWarnSeconds: "cert_expiry_warn_seconds",
  certExpiryCriticalSeconds: "cert_expiry_critical_seconds",
};
for (const [helmKey, thresholdsKey] of Object.entries(helmSloMap)) {
  const expected = thresholds[thresholdsKey];
  const actual = helmSlo[helmKey];
  if (actual === undefined) {
    errors.push(`[helm/chart/values.yaml] Missing slo.${helmKey} for thresholds.json ${thresholdsKey}`);
  } else if (Math.abs(actual - expected) > 1e-9) {
    errors.push(`[helm/chart/values.yaml] slo.${helmKey} = ${actual} but thresholds.json ${thresholdsKey} = ${expected}`);
  }
}

// 1. Request Latency (0.3s)
checkMatch(alertingRules, "alerting.rules.yml", /> 0\.3/, `request latency p95 threshold of ${thresholds.request_latency_p95_seconds}s`);
checkMatch(readme, "slo/README.md", /300 ms/, "documented 300 ms request latency target");

// 2. Error Rate (0.005 budget, 0.072 fast burn, 0.030 slow burn)
const errTargetRegex = new RegExp(`sli:error_budget:success:30d[\\s\\S]*?\\/ ${thresholds.error_rate_target_ratio}`);
checkMatch(recordingRules, "recording.rules.yml", errTargetRegex, `HTTP error budget denominator ${thresholds.error_rate_target_ratio}`);
checkMatch(alertingRules, "alerting.rules.yml", />= 0\.072/, `error rate fast burn ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", />= 0\.030/, `error rate slow burn ${thresholds.slow_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:error_rate:5m >= 0\.072/, `error rate fast-burn short window (${thresholds.fast_burn_short_window}) at ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:error_rate:30m >= 0\.030/, `error rate slow-burn short window (${thresholds.slow_burn_short_window}) at ${thresholds.slow_burn_threshold}`);
checkMatch(readme, "slo/README.md", /99\.5%/, "documented 99.5% error budget target");

// 3. DB Latency (0.05s)
checkMatch(alertingRules, "alerting.rules.yml", /> 0\.05/, `DB query latency threshold of ${thresholds.db_query_latency_p95_seconds}s`);
checkMatch(readme, "slo/README.md", /50 ms/, "documented 50 ms DB latency target");

// 4. Cache Hit Ratio (0.85)
checkMatch(alertingRules, "alerting.rules.yml", /< 0\.85/, `cache hit ratio threshold of ${thresholds.cache_hit_ratio_min}`);
checkMatch(readme, "slo/README.md", /85%/, "documented 85% cache hit ratio target");

// 5. Cert Renewal — expiry-driven (warn <=14d, page <=7d). The old failure-rate
//    ratio alerts were removed because `rate()` over a fixed window is 0/0 = NaN
//    when no renewal happened in the window and could never fire; the alertable
//    signal is the continuous `cert_time_to_expiry_seconds` gauge.
const certExpiryWarn = thresholds.cert_expiry_warn_seconds;
const certExpiryCritical = thresholds.cert_expiry_critical_seconds;
checkMatch(
  alertingRules, "alerting.rules.yml",
  new RegExp(`cert_time_to_expiry_seconds\\{otel_scope_name="status-list-server"\\} <= ${certExpiryWarn}`),
  `cert expiry warn threshold <= ${certExpiryWarn}s (${certExpiryWarn / 86400}d)`
);
checkMatch(
  alertingRules, "alerting.rules.yml",
  new RegExp(`cert_time_to_expiry_seconds\\{otel_scope_name="status-list-server"\\} <= ${certExpiryCritical}`),
  `cert expiry critical threshold <= ${certExpiryCritical}s (${certExpiryCritical / 86400}d)`
);
checkMatch(readme, "slo/README.md", /14 days/, "documented 14-day cert expiry warn target");

// 6. Token Generation Failure Rate (0.005 budget, 0.072 fast burn, 0.030 slow burn)
const tokenErrTargetRegex = new RegExp(`sli:token_gen_error_budget:30d[\\s\\S]*?\\/ ${thresholds.token_gen_failure_rate_max}`);
checkMatch(recordingRules, "recording.rules.yml", tokenErrTargetRegex, `token gen error budget denominator ${thresholds.token_gen_failure_rate_max}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:1h >= 0\.072/, `token gen fast burn ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:5m >= 0\.072/, `token gen fast-burn short window (${thresholds.fast_burn_short_window}) at ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:6h >= 0\.030/, `token gen slow burn ${thresholds.slow_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:30m >= 0\.030/, `token gen slow-burn short window (${thresholds.slow_burn_short_window}) at ${thresholds.slow_burn_threshold}`);
checkMatch(readme, "slo/README.md", /0\.5%/, "documented 0.5% token gen failure target");

// 7. Budget-critical gates (0.1 remaining-error-budget)
const errBudgetCritThreshold = thresholds.error_budget_critical_threshold;
checkMatch(
  alertingRules,
  "alerting.rules.yml",
  new RegExp(`sli:error_budget:success:30d < ${errBudgetCritThreshold}`),
  `error budget critical gate < ${errBudgetCritThreshold}`
);
checkMatch(
  alertingRules,
  "alerting.rules.yml",
  new RegExp(`sli:token_gen_error_budget:30d < ${errBudgetCritThreshold}`),
  `token gen error budget critical gate < ${errBudgetCritThreshold}`
);

if (errors.length > 0) {
  console.error("❌ SLO threshold lint failed:");
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
} else {
  console.log("✅ All SLO thresholds are in sync with thresholds.json!");
}
