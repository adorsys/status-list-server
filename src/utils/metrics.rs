use color_eyre::eyre::{Context, Result};
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use prometheus::{Encoder, Registry, TextEncoder};

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

    // Install as global so `opentelemetry::global::meter()` works everywhere
    opentelemetry::global::set_meter_provider(provider.clone());
    Ok(provider)
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
