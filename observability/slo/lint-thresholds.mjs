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

let errors = [];

function checkMatch(content, filename, pattern, description) {
  if (!pattern.test(content)) {
    errors.push(`[${filename}] Expected ${description} matching ${pattern}`);
  }
}

// 1. Request Latency (0.3s)
checkMatch(alertingRules, "alerting.rules.yml", /> 0\.3/, `request latency p95 threshold of ${thresholds.request_latency_p95_seconds}s`);
checkMatch(readme, "slo/README.md", /300 ms/, "documented 300 ms request latency target");

// 2. Error Rate (0.005 budget, 0.072 fast burn, 0.030 slow burn)
checkMatch(recordingRules, "recording.rules.yml", /\/ 0\.005/, `error budget denominator ${thresholds.error_rate_target_ratio}`);
checkMatch(alertingRules, "alerting.rules.yml", />= 0\.072/, `error rate fast burn ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", />= 0\.030/, `error rate slow burn ${thresholds.slow_burn_threshold}`);
checkMatch(readme, "slo/README.md", /99\.5%/, "documented 99.5% error budget target");

// 3. DB Latency (0.05s)
checkMatch(alertingRules, "alerting.rules.yml", /> 0\.05/, `DB query latency threshold of ${thresholds.db_query_latency_p95_seconds}s`);
checkMatch(readme, "slo/README.md", /50 ms/, "documented 50 ms DB latency target");

// 4. Cache Hit Ratio (0.85)
checkMatch(alertingRules, "alerting.rules.yml", /< 0\.85/, `cache hit ratio threshold of ${thresholds.cache_hit_ratio_min}`);
checkMatch(readme, "slo/README.md", /85%/, "documented 85% cache hit ratio target");

// 5. Cert Renewal Failure Rate (0.01)
checkMatch(alertingRules, "alerting.rules.yml", />= 0\.01/, `cert renewal failure rate threshold of ${thresholds.cert_renewal_failure_rate_max}`);
checkMatch(readme, "slo/README.md", /1%/, "documented 1% cert renewal failure rate target");

// 6. Token Generation Failure Rate (0.005 budget, 0.072 fast burn, 0.030 slow burn)
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:1h >= 0\.072/, `token gen fast burn ${thresholds.fast_burn_threshold}`);
checkMatch(alertingRules, "alerting.rules.yml", /sli:token_gen_failure_rate:6h >= 0\.030/, `token gen slow burn ${thresholds.slow_burn_threshold}`);
checkMatch(readme, "slo/README.md", /0\.5%/, "documented 0.5% token gen failure target");

if (errors.length > 0) {
  console.error("❌ SLO threshold lint failed:");
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
} else {
  console.log("✅ All SLO thresholds are in sync with thresholds.json!");
}
