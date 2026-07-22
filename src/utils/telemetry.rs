//! Unified telemetry initialization for tracing, metrics, and logging.

use color_eyre::eyre::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use prometheus::Registry;
use tracing_subscriber::{
    EnvFilter, Registry as TracingRegistry, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::config::{ENV_PRODUCTION, TelemetryConfig};

/// Guard that shuts down the OpenTelemetry tracer provider on drop, ensuring
/// all pending spans are flushed before the process exits.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(e) = provider.shutdown() {
                tracing::error!("OpenTelemetry tracer shutdown error: {e}");
            }
        }
    }
}

/// Initializes the global telemetry stack (tracing + metrics) based on the
/// provided configuration.
///
/// Returns a [`TelemetryGuard`] that must be held until application
/// shutdown. Also returns a [`prometheus::Registry`] that the `/metrics`
/// endpoint uses to render Prometheus metrics.
pub fn init_telemetry(config: &TelemetryConfig) -> color_eyre::Result<(TelemetryGuard, Registry)> {
    let is_prod = config.environment.eq_ignore_ascii_case(ENV_PRODUCTION);
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "status-list-server".to_string());

    let resource = Resource::builder().with_service_name(service_name).build();

    // Prometheus metrics registry (always active)
    let prometheus_registry = Registry::new();

    // Build the tracing subscriber
    let env_filter = build_env_filter();

    if is_prod && config.enabled {
        // Production: JSON stdout + OTLP trace export
        let tracer_provider = build_otlp_tracer_provider(config, resource)?;

        let tracer = tracer_provider.tracer("status-list-server");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true);

        TracingRegistry::default()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .try_init()?;

        tracing::info!(otlp_endpoint = %config.otlp_endpoint, "telemetry initialized");

        Ok((
            TelemetryGuard {
                tracer_provider: Some(tracer_provider),
            },
            prometheus_registry,
        ))
    } else {
        // Development: pretty-printed stdout
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(false)
            .with_file(true)
            .with_line_number(true);

        TracingRegistry::default()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()?;

        tracing::info!("telemetry initialized: stdout logging only");

        Ok((
            TelemetryGuard {
                tracer_provider: None,
            },
            prometheus_registry,
        ))
    }
}

/// Builds an OTLP-backed tracer provider with batch export.
fn build_otlp_tracer_provider(
    config: &TelemetryConfig,
    resource: Resource,
) -> color_eyre::Result<SdkTracerProvider> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};

    let sampler = if (config.sampler_ratio - 1.0_f64).abs() < f64::EPSILON {
        Sampler::AlwaysOn
    } else if config.sampler_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sampler_ratio)
    };

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .wrap_err("failed to build OTLP span exporter")?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(resource)
        .build())
}

/// Constructs the [`EnvFilter`] from the `RUST_LOG` env var with sensible
/// defaults for noisy dependencies.
fn build_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("hyper::proto=info".parse().expect("valid directive"))
            .add_directive("tower_http::trace=debug".parse().expect("valid directive"))
            .add_directive("h2=info".parse().expect("valid directive"))
            .add_directive("tonic=info".parse().expect("valid directive"))
    })
}
