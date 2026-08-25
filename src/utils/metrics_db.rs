//! Database query latency and error SLI instruments.
//!
//! These back the DB-latency and DB-error series used by the SLO dashboards and
//! burn-rate alerts in `observability/`:
//! - `db_query_duration_seconds` – histogram of storage-query latency
//! - `db_query_errors_total` – counter of failed storage queries
//!
//! Handles are cached on first use (they are only ever needed after
//! `init_telemetry`/`setup_metrics` has installed the global provider, so the
//! cached handles are valid).

use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use std::{
    future::Future,
    sync::{Mutex, OnceLock},
    time::Instant,
};

const QUERY_DURATION_METRIC: &str = "db_query_duration";
const QUERY_ERRORS_METRIC: &str = "db_query_errors";

/// Bucket boundaries (seconds) tuned to this service's DB SLO target of p95 < 50 ms.
const QUERY_BUCKETS: &[f64] = &[
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

#[derive(Clone)]
struct DbMetrics {
    duration: Histogram<f64>,
    errors: Counter<u64>,
}

fn db_metrics() -> DbMetrics {
    static METRICS: OnceLock<Mutex<Option<(u64, DbMetrics)>>> = OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = global::meter("status-list-server");
        DbMetrics {
            duration: meter
                .f64_histogram(QUERY_DURATION_METRIC)
                .with_description("Duration of database queries")
                .with_unit("s")
                .with_boundaries(QUERY_BUCKETS.to_vec())
                .build(),
            errors: meter
                .u64_counter(QUERY_ERRORS_METRIC)
                .with_description("Total number of failed database queries")
                .build(),
        }
    })
}

/// Record a completed (successful or failed) query's duration.
pub(crate) fn record_db_query(operation: &'static str, resource: &'static str, seconds: f64) {
    db_metrics().duration.record(
        seconds,
        &[
            KeyValue::new("operation", operation),
            KeyValue::new("resource", resource),
        ],
    );
}

/// Record a query failure so an error rate is derivable from
/// `db_query_errors_total / db_query_duration_seconds_count`.
pub(crate) fn record_db_query_error(operation: &'static str, resource: &'static str) {
    db_metrics().errors.add(
        1,
        &[
            KeyValue::new("operation", operation),
            KeyValue::new("resource", resource),
        ],
    );
}

/// Run `fut`, timing it and recording latency + an error counter on `Err`.
pub(crate) async fn time_query<T, E, F>(
    operation: &'static str,
    resource: &'static str,
    fut: F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    let result = fut.await;
    record_db_query(operation, resource, start.elapsed().as_secs_f64());
    if result.is_err() {
        record_db_query_error(operation, resource);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{TelemetryConfig, TelemetryEnvironment},
        utils::metrics::{metrics_test_lock, setup_metrics},
    };
    use opentelemetry_sdk::Resource;
    use prometheus::{Encoder, Registry, TextEncoder};

    #[test]
    fn db_metrics_record_duration_and_error_series() {
        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        record_db_query("find", "status_list", 0.003);
        record_db_query_error("find", "status_list");

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");

        assert!(
            body.contains("db_query_duration_seconds_bucket"),
            "expected duration histogram; body:\n{body}"
        );
        assert!(
            body.contains(
                "db_query_errors_total{operation=\"find\",resource=\"status_list\",otel_scope_name=\"status-list-server\"} 1"
            ),
            "expected error counter; body:\n{body}"
        );
    }

    #[tokio::test]
    async fn time_query_records_error_only_on_err() {
        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        let ok: Result<(), &str> = time_query("op", "res", async { Ok(()) }).await;
        assert!(ok.is_ok());

        let err: Result<(), &str> = time_query("op", "res", async { Err("boom") }).await;
        assert_eq!(err, Err("boom"));

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");
        assert!(
            body.contains(
                "db_query_errors_total{operation=\"op\",resource=\"res\",otel_scope_name=\"status-list-server\"} 1"
            ),
            "expected exactly one error counter; body:\n{body}"
        );
    }
}
