use color_eyre::eyre::{Context, Result};
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use prometheus::{Encoder, Registry, TextEncoder};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::TelemetryConfig;

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
    Ok(provider)
}

#[derive(Clone, Copy)]
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

        for expected in [
            "process_cpu_seconds_total",
            "process_open_fds",
            "process_max_fds",
            "process_virtual_memory_bytes",
            "process_virtual_memory_max_bytes",
            "process_resident_memory_bytes",
            "process_start_time_seconds",
            "process_threads",
        ] {
            assert!(
                families.contains(expected),
                "missing process metric family {expected}; got {families:?}"
            );
        }
    }
}
