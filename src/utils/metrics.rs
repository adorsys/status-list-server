use color_eyre::eyre::{Context, Result};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};

/// Initialize the OpenTelemetry metrics pipeline backed by a Prometheus
/// registry. Returns the [`SdkMeterProvider`] that instruments use to create
/// counters, histograms, etc.
pub(crate) fn setup_metrics(registry: &Registry) -> Result<SdkMeterProvider> {
    let prometheus_exporter = exporter()
        .with_registry(registry.clone())
        .build()
        .wrap_err("Failed to build Prometheus exporter")?;

    let provider = SdkMeterProvider::builder()
        .with_reader(prometheus_exporter)
        .build();

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
