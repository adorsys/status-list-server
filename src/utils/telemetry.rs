use color_eyre::eyre::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    metrics::SdkMeterProvider,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use prometheus::Registry;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::{
    EnvFilter, Layer as _, Registry as TracingRegistry,
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{config::TelemetryConfig, utils::metrics::setup_metrics};

/// Flushes pending telemetry on drop; hold it until shutdown.
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

pub struct HeaderExtractor<'a>(pub &'a axum::http::HeaderMap);

impl<'a> opentelemetry::propagation::Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

pub fn make_http_request_span(request: &axum::http::Request<axum::body::Body>) -> tracing::Span {
    let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let span = tracing::info_span!(
        "HTTP request",
        http.method = %request.method(),
        http.uri = %request.uri(),
        otel.kind = "server",
    );
    let _ = span.set_parent(parent_context);
    span
}

pub fn init_telemetry(config: &TelemetryConfig) -> color_eyre::Result<(TelemetryGuard, Registry)> {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "status-list-server".to_string());

    let resource = Resource::builder().with_service_name(service_name).build();

    // Always on, even with OTLP disabled.
    let prometheus_registry = Registry::new();
    let meter_provider = setup_metrics(&prometheus_registry, config, resource.clone())?;

    let env_filter = build_env_filter();

    let (tracer_provider, logger_provider) = if config.enabled {
        let tracer_provider = build_otlp_tracer_provider(config, resource.clone())?;
        let logger_provider = build_otlp_logger_provider(config, resource)?;

        if config.environment.is_production() {
            let tracer = tracer_provider.tracer("status-list-server");
            let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let otel_log_filter = Targets::new()
                .with_default(LevelFilter::INFO)
                .with_target("opentelemetry", LevelFilter::OFF)
                .with_target("tonic", LevelFilter::OFF)
                .with_target("h2", LevelFilter::OFF)
                .with_target("hyper", LevelFilter::OFF);
            let otel_log_layer =
                OpenTelemetryTracingBridge::new(&logger_provider).with_filter(otel_log_filter);

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
        } else {
            let tracer = tracer_provider.tracer("status-list-server");
            let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let otel_log_filter = Targets::new()
                .with_default(LevelFilter::INFO)
                .with_target("opentelemetry", LevelFilter::OFF)
                .with_target("tonic", LevelFilter::OFF)
                .with_target("h2", LevelFilter::OFF)
                .with_target("hyper", LevelFilter::OFF);
            let otel_log_layer =
                OpenTelemetryTracingBridge::new(&logger_provider).with_filter(otel_log_filter);

            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_file(true)
                .with_line_number(true);

            TracingRegistry::default()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_trace_layer)
                .with(otel_log_layer)
                .try_init()?;
        }

        tracing::info!(otlp_endpoint = %config.otlp_endpoint, "telemetry initialized with OTLP export");

        (Some(tracer_provider), Some(logger_provider))
    } else {
        if config.environment.is_production() {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true);

            TracingRegistry::default()
                .with(env_filter)
                .with(fmt_layer)
                .try_init()?;
        } else {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_file(true)
                .with_line_number(true);

            TracingRegistry::default()
                .with(env_filter)
                .with(fmt_layer)
                .try_init()?;
        }

        tracing::info!("telemetry initialized: stdout logging only");

        (None, None)
    };

    Ok((
        TelemetryGuard {
            tracer_provider,
            meter_provider,
            logger_provider,
        },
        prometheus_registry,
    ))
}

fn build_otlp_tracer_provider(
    config: &TelemetryConfig,
    resource: Resource,
) -> color_eyre::Result<SdkTracerProvider> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sampler_ratio)));

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

/// RUST_LOG wins; otherwise info with noisy crates turned down.
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
        if let Ok((guard, _registry)) = result {
            assert!(guard.tracer_provider.is_none());
            assert!(guard.logger_provider.is_none());
        }
    }

    #[test]
    fn test_init_telemetry_prod_mode_providers() {
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
