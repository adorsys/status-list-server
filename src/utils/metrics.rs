use color_eyre::eyre::{Context, Result};
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Gauge, MeterProvider as _},
};
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use prometheus::{Encoder, Registry, TextEncoder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::TelemetryConfig;

#[cfg(test)]
static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());
/// Bumped each time the global meter provider is (re)installed by
/// [`setup_metrics`]. Recorders that cache instrument handles key their cache
/// on this so a fresh provider (e.g. every metric test) doesn't keep writing to
/// a stale, previously-dropped provider.
static METER_PROVIDER_GENERATION: AtomicU64 = AtomicU64::new(0);
static ROTATION_METRICS: OnceLock<Mutex<Option<(u64, RotationMetrics)>>> = OnceLock::new();

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) const TARGET_DATABASE: &str = "database";
#[cfg(any(not(feature = "acme"), test))]
pub(crate) const TARGET_TOKEN_SIGNING_KEY: &str = "token_signing_key";

#[derive(Clone)]
struct RotationMetrics {
    total: Counter<u64>,
    last_success_timestamp: Gauge<f64>,
}

/// The current global meter-provider generation.
pub(crate) fn provider_generation() -> u64 {
    METER_PROVIDER_GENERATION.load(Ordering::Relaxed)
}

/// Return `T` from a per-provider-generation cache, rebuilding it with `build`
/// whenever the global meter provider has changed (e.g. after a re-run of
/// `setup_metrics` in tests).
pub(crate) fn cached_instruments<T: Clone>(
    slot: &'static OnceLock<Mutex<Option<(u64, T)>>>,
    build: impl FnOnce() -> T,
) -> T {
    let generation = provider_generation();
    let cell = slot.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match &*guard {
        Some((g, value)) if *g == generation => value.clone(),
        _ => {
            let value = build();
            *guard = Some((generation, value.clone()));
            value
        }
    }
}

#[cfg(test)]
pub(crate) fn metrics_test_lock() -> std::sync::MutexGuard<'static, ()> {
    METRICS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn rotation_metrics() -> RotationMetrics {
    cached_instruments(&ROTATION_METRICS, || {
        let meter = global::meter("status-list-server");
        RotationMetrics {
            total: meter
                .u64_counter("credential_rotation_total")
                .with_description("Credential rotation attempts by target and outcome.")
                .build(),
            last_success_timestamp: meter
                .f64_gauge("credential_rotation_last_success_timestamp")
                .with_description("Unix timestamp of the last successful credential rotation.")
                .with_unit("s")
                .build(),
        }
    })
}

pub(crate) fn record_rotation(target: &'static str, success: bool) {
    let instruments = rotation_metrics();
    let outcome = if success { "success" } else { "failure" };
    let attrs = [
        KeyValue::new("target", target),
        KeyValue::new("outcome", outcome),
    ];

    instruments.total.add(1, &attrs);

    if success {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or_default();
        instruments
            .last_success_timestamp
            .record(timestamp, &[KeyValue::new("target", target)]);
    }
}

/// Initialize the OpenTelemetry metrics pipeline before any instruments are
/// created. Metrics are always exposed through the in-process Prometheus
/// registry. In production, they are also pushed to the Collector over OTLP.
pub(crate) fn setup_metrics(
    registry: &Registry,
    config: &TelemetryConfig,
    resource: Resource,
) -> Result<SdkMeterProvider> {
    let prometheus_exporter = exporter()
        .with_registry(registry.clone())
        .build()
        .wrap_err("Failed to build Prometheus exporter")?;

    let mut builder = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(prometheus_exporter);

    if config.enabled && config.environment.is_production() {
        let otlp_exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&config.otlp_endpoint)
            .build()
            .wrap_err("Failed to build OTLP metric exporter")?;
        builder = builder.with_reader(PeriodicReader::builder(otlp_exporter).build());
    }

    let provider = builder.build();
    register_process_observers(&provider);

    // Install as global so `opentelemetry::global::meter()` works everywhere
    opentelemetry::global::set_meter_provider(provider.clone());
    METER_PROVIDER_GENERATION.fetch_add(1, Ordering::Relaxed);
    Ok(provider)
}

#[derive(Clone, Copy, Debug)]
struct ProcessMetrics {
    cpu_seconds_total: Option<f64>,
    open_fds: Option<u64>,
    max_fds: Option<u64>,
    virtual_memory_bytes: Option<u64>,
    virtual_memory_max_bytes: Option<u64>,
    resident_memory_bytes: Option<u64>,
    start_time_seconds: Option<u64>,
    threads: Option<u64>,
}

struct ProcessSnapshotCache {
    last_updated: Instant,
    snapshot: ProcessMetrics,
}

static PROCESS_CACHE: Mutex<Option<ProcessSnapshotCache>> = Mutex::new(None);

fn get_process_snapshot() -> ProcessMetrics {
    let now = Instant::now();
    let mut cache = PROCESS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref c) = *cache
        && now.duration_since(c.last_updated) < Duration::from_millis(500)
    {
        return c.snapshot;
    }
    let m = metrics_process::collector::collect();
    let snapshot = ProcessMetrics {
        cpu_seconds_total: m.cpu_seconds_total,
        open_fds: m.open_fds,
        max_fds: m.max_fds,
        virtual_memory_bytes: m.virtual_memory_bytes,
        virtual_memory_max_bytes: m.virtual_memory_max_bytes,
        resident_memory_bytes: m.resident_memory_bytes,
        start_time_seconds: m.start_time_seconds,
        threads: m.threads,
    };
    *cache = Some(ProcessSnapshotCache {
        last_updated: now,
        snapshot,
    });
    snapshot
}

fn register_process_observers(provider: &SdkMeterProvider) {
    let meter = provider.meter("status-list-server");

    meter
        .f64_observable_counter("process_cpu")
        .with_description("Total user and system CPU time spent in seconds.")
        .with_unit("s")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().cpu_seconds_total {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_open_fds")
        .with_description("Number of open file descriptors.")
        .with_unit("{fd}")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().open_fds {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_max_fds")
        .with_description("Maximum number of open file descriptors.")
        .with_unit("{fd}")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().max_fds {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_virtual_memory")
        .with_description("Virtual memory size in bytes.")
        .with_unit("By")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().virtual_memory_bytes {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_virtual_memory_max")
        .with_description("Maximum amount of virtual memory available in bytes.")
        .with_unit("By")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().virtual_memory_max_bytes {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_resident_memory")
        .with_description("Resident memory size in bytes.")
        .with_unit("By")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().resident_memory_bytes {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_start_time")
        .with_description("Start time of the process since Unix epoch in seconds.")
        .with_unit("s")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().start_time_seconds {
                observer.observe(value, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("process_threads")
        .with_description("Number of OS threads in the process.")
        .with_unit("{thread}")
        .with_callback(|observer| {
            if let Some(value) = get_process_snapshot().threads {
                observer.observe(value, &[]);
            }
        })
        .build();
}

/// Render all collected metrics in the Prometheus text exposition format.
pub(crate) async fn metrics_handler(registry: Registry) -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = vec![];
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode metrics: {e}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TelemetryConfig, TelemetryEnvironment};
    use opentelemetry_sdk::Resource;

    #[test]
    fn setup_metrics_registers_process_metric_families() {
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

        let families = registry
            .gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect::<std::collections::HashSet<_>>();

        // Observers only report when the collector yields a value, and
        // `metrics_process` does not expose every field on every platform.
        // Asserting the full set would test the host OS rather than the
        // registration wiring, so derive it from what the collector reports.
        let snapshot = get_process_snapshot();
        let expected = [
            (
                "process_cpu_seconds_total",
                snapshot.cpu_seconds_total.is_some(),
            ),
            ("process_open_fds", snapshot.open_fds.is_some()),
            ("process_max_fds", snapshot.max_fds.is_some()),
            (
                "process_virtual_memory_bytes",
                snapshot.virtual_memory_bytes.is_some(),
            ),
            (
                "process_virtual_memory_max_bytes",
                snapshot.virtual_memory_max_bytes.is_some(),
            ),
            (
                "process_resident_memory_bytes",
                snapshot.resident_memory_bytes.is_some(),
            ),
            (
                "process_start_time_seconds",
                snapshot.start_time_seconds.is_some(),
            ),
            ("process_threads", snapshot.threads.is_some()),
        ];

        // Without a floor, a `setup_metrics` that registered no observers at all
        // would filter every field out and pass the loop below vacuously. Six is
        // what `metrics-process` reports on the thinnest supported platform
        // (Windows, missing `virtual_memory_max_bytes` and `threads`).
        const ALWAYS_AVAILABLE: usize = 6;
        let available = expected.iter().filter(|(_, available)| *available).count();
        assert!(
            available >= ALWAYS_AVAILABLE,
            "collector reported only {available} of {ALWAYS_AVAILABLE} \
             universally-available process metrics on this platform \
             ({snapshot:?}); the assertions below would be vacuous"
        );

        for (family, available) in expected {
            if !available {
                continue;
            }
            assert!(
                families.contains(family),
                "collector reported a value for {family} but it was not exported; \
                 got {families:?}"
            );
        }
    }

    #[test]
    fn rotation_metrics_are_exported_with_target_and_outcome_labels() {
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

        record_rotation(TARGET_TOKEN_SIGNING_KEY, true);
        record_rotation(TARGET_TOKEN_SIGNING_KEY, false);

        let rendered = tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(metrics_handler(registry));
        assert!(rendered.contains("credential_rotation_total"));
        assert!(rendered.contains("credential_rotation_last_success_timestamp"));
        assert!(rendered.contains("target=\"token_signing_key\""));
        assert!(rendered.contains("outcome=\"success\""));
        assert!(rendered.contains("outcome=\"failure\""));
    }
}
