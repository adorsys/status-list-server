//! HTTP request latency and count SLI instruments.
//!
//! These are the two series the SLO dashboards and burn-rate alerts in
//! `observability/` query:
//! - `http_server_duration_seconds` – a histogram of server-side request latency
//! - `http_server_requests_total` – a counter of requests by status class
//!
//! The instruments are created lazily on first use through a [`OnceLock`]. The
//! first request only ever arrives after `init_telemetry`/`setup_metrics` has
//! installed the global meter provider, so the cached handles are valid and are
//! never no-ops (the `http` crate's "resolve the meter per event" rule from
//! `src/server/error.rs` exists precisely because a handle taken *before* the
//! provider is installed binds a permanent no-op).

use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use std::sync::{Mutex, OnceLock};

const DURATION_METRIC: &str = "http_server_duration";
const REQUESTS_TOTAL_METRIC: &str = "http_server_requests";

/// Histogram bucket boundaries (seconds) tuned to this service's SLO target of
/// p95 < 300 ms. The upper buckets still catch slow requests without exploding
/// cardinality.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A pair of HTTP SLI instruments bound to the `status-list-server` meter.
#[derive(Clone)]
pub(crate) struct HttpMetrics {
    duration: Histogram<f64>,
    requests: Counter<u64>,
}

impl HttpMetrics {
    fn new() -> Self {
        let meter = global::meter("status-list-server");

        let duration = meter
            .f64_histogram(DURATION_METRIC)
            .with_description("HTTP server request handling duration")
            .with_unit("s")
            .with_boundaries(DURATION_BUCKETS.to_vec())
            .build();

        let requests = meter
            .u64_counter(REQUESTS_TOTAL_METRIC)
            .with_description("Total number of HTTP requests handled by status class")
            .build();

        Self { duration, requests }
    }

    /// Record one completed request.
    ///
    /// `route` must be the bounded route pattern (e.g. `/status-lists/{list_id}`),
    /// never a URI with path parameters substituted, to keep label cardinality
    /// bounded.
    pub(crate) fn record(&self, method: &str, route: &str, status_class: &str, seconds: f64) {
        let duration_attrs = [
            KeyValue::new("method", method.to_string()),
            KeyValue::new("route", route.to_string()),
            KeyValue::new("status", status_class.to_string()),
        ];
        self.duration.record(seconds, &duration_attrs);

        let count_attrs = [
            KeyValue::new("method", method.to_string()),
            KeyValue::new("route", route.to_string()),
            KeyValue::new("status_class", status_class.to_string()),
        ];
        self.requests.add(1, &count_attrs);
    }
}

/// The process-wide `HttpMetrics`, rebuilt whenever the global meter provider
/// changes (see `cached_instruments`).
fn shared() -> HttpMetrics {
    static METRICS: OnceLock<Mutex<Option<(u64, HttpMetrics)>>> = OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, HttpMetrics::new)
}

/// Record an HTTP request/response pair emitted from the axum metrics layer.
pub(crate) fn record_request(method: &str, route: &str, status_class: &str, seconds: f64) {
    shared().record(method, route, status_class, seconds);
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
    fn http_metrics_record_duration_and_counter_series() {
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

        record_request("GET", "/status-lists/{list_id}", "2xx", 0.012);
        record_request("GET", "/status-lists/{list_id}", "5xx", 0.300);

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");

        assert!(
            body.contains(
                "http_server_requests_total{method=\"GET\",route=\"/status-lists/{list_id}\",status_class=\"2xx\",otel_scope_name=\"status-list-server\"} 1"
            ),
            "expected 2xx request counter; body:\n{body}"
        );
        assert!(
            body.contains(
                "http_server_requests_total{method=\"GET\",route=\"/status-lists/{list_id}\",status_class=\"5xx\",otel_scope_name=\"status-list-server\"} 1"
            ),
            "expected 5xx request counter; body:\n{body}"
        );
        assert!(
            body.contains("http_server_duration_seconds_bucket"),
            "expected duration histogram; body:\n{body}"
        );
        assert!(
            body.contains("http_server_duration_seconds_count"),
            "expected duration histogram count; body:\n{body}"
        );
    }
}
