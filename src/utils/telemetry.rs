//! Unified telemetry initialization for tracing, metrics, and logging.

use color_eyre::eyre::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    metrics::SdkMeterProvider,
    trace::{Sampler, SdkTracerProvider},
};
use prometheus::Registry;
use tracing_subscriber::{
    EnvFilter, Registry as TracingRegistry, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::{config::TelemetryConfig, utils::metrics::setup_metrics};

/// Guard that shuts down OpenTelemetry providers on drop, ensuring pending
/// telemetry is flushed before the process exits.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: SdkMeterProvider,
    logger_provider: Option<SdkLoggerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.logger_provider.take()
            && let Err(e) = provider.shutdown()
        {
            tracing::error!("OpenTelemetry logger shutdown error: {e}");
        }
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            tracing::error!("OpenTelemetry tracer shutdown error: {e}");
        }
        if let Err(e) = self.meter_provider.shutdown() {
            tracing::error!("OpenTelemetry meter shutdown error: {e}");
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
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "status-list-server".to_string());

    let resource = Resource::builder().with_service_name(service_name).build();

    // Prometheus metrics registry (always active)
    let prometheus_registry = Registry::new();
    let meter_provider = setup_metrics(&prometheus_registry, config, resource.clone())?;

    // Build the tracing subscriber
    let env_filter = build_env_filter();

    if config.enabled && config.environment.is_production() {
        // Production: JSON stdout + OTLP trace and log export.
        let tracer_provider = build_otlp_tracer_provider(config, resource.clone())?;
        let logger_provider = build_otlp_logger_provider(config, resource)?;

        let tracer = tracer_provider.tracer("status-list-server");
        let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true);

        TracingRegistry::default()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_trace_layer)
            .with(otel_log_layer)
            .try_init()?;

        tracing::info!(otlp_endpoint = %config.otlp_endpoint, "telemetry initialized");

        Ok((
            TelemetryGuard {
                tracer_provider: Some(tracer_provider),
                meter_provider,
                logger_provider: Some(logger_provider),
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
                meter_provider,
                logger_provider: None,
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

fn build_otlp_logger_provider(
    config: &TelemetryConfig,
    resource: Resource,
) -> color_eyre::Result<SdkLoggerProvider> {
    use opentelemetry_otlp::{LogExporter, WithExportConfig};

    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .wrap_err("failed to build OTLP log exporter")?;

    Ok(SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TelemetryConfig, TelemetryEnvironment};

    #[test]
    fn test_init_telemetry_dev_mode() {
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };

        let result = init_telemetry(&config);
        // init_telemetry succeeds or returns try_init error if subscriber already set by another test
        if let Ok((guard, _registry)) = result {
            assert!(guard.tracer_provider.is_none());
            assert!(guard.logger_provider.is_none());
        }
    }

    #[test]
    fn test_init_telemetry_prod_mode_providers() {
        // The OTLP/tonic exporter builder touches the Tokio reactor; wrap in a
        // single-threaded runtime so the test is self-contained.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let config = TelemetryConfig {
                environment: TelemetryEnvironment::Production,
                otlp_endpoint: "http://localhost:4317".to_string(),
                sampler_ratio: 1.0,
                enabled: true,
            };

            let resource = Resource::builder().with_service_name("test").build();
            let tracer_provider = build_otlp_tracer_provider(&config, resource.clone());
            assert!(tracer_provider.is_ok());

            let logger_provider = build_otlp_logger_provider(&config, resource);
            assert!(logger_provider.is_ok());
        });
    }
}
