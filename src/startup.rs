use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, MatchedPath},
    http::Request,
    middleware::{self, Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use color_eyre::eyre::{Context, eyre};
use governor::middleware::NoOpMiddleware;
use hyper::Method;
use prometheus::Registry;
use tokio::net::TcpListener;
use tower_governor::{
    GovernorLayer,
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor},
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

const AGGREGATION_ROUTE_PATH: &str = "/api/v1/aggregation";

use crate::config::Config;
use crate::server::AppState;
use crate::server::auth::auth;
use crate::server::handlers::{
    credential_handler, get_aggregation, get_status_list, publish_status, update_status,
};
use crate::server::health;
use crate::utils::metrics::metrics_handler;

async fn welcome() -> impl IntoResponse {
    "Status list Server"
}

pub struct HttpServer {
    listener: TcpListener,
    router: Router,
}

impl HttpServer {
    pub async fn new(
        config: &Config,
        state: AppState,
        prometheus_registry: Registry,
    ) -> color_eyre::Result<Self> {
        let cors = CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_origin(Any)
            .allow_headers(Any);

        let max_body_size = config.limits.max_body_size_bytes;

        let (strict_governor, issuer_governor, permissive_governor) =
            build_governor_configs(&config.rate_limit)?;

        let mut router = Router::new()
            .route("/", get(welcome))
            .route("/health", get(health::live))
            .route("/health/live", get(health::live))
            .route("/health/ready", get(health::ready))
            .nest(
                "/api/v1",
                api_v1_routes(
                    state.clone(),
                    strict_governor.clone(),
                    issuer_governor.clone(),
                    permissive_governor.clone(),
                ),
            )
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(crate::utils::telemetry::make_http_request_span),
            )
            .layer(middleware::from_fn(track_http_metrics))
            .layer(CatchPanicLayer::new())
            .layer(cors)
            .layer(RequestBodyLimitLayer::new(max_body_size))
            .layer(DefaultBodyLimit::disable())
            .with_state(state);

        router = attach_metrics(router, config, prometheus_registry);

        validate_aggregation_uri(config)?;

        let listener = TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await
            .wrap_err_with(|| format!("Failed to bind to port {}", config.server.port))?;

        Ok(Self { router, listener })
    }

    pub async fn run(self) -> color_eyre::Result<()> {
        tracing::info!("listening on {}", self.listener.local_addr()?);
        axum::serve(
            self.listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .wrap_err("Failed to start HTTP server")?;
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

type GovernorPolicies = (
    Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
    Arc<GovernorConfig<SmartIpKeyExtractor, NoOpMiddleware>>,
    Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
);

fn build_governor_configs(
    config: &crate::config::RateLimitConfig,
) -> color_eyre::Result<GovernorPolicies> {
    let strict = Arc::new(
        GovernorConfigBuilder::default()
            .burst_size(config.strict_burst_size)
            .period(Duration::from_secs(config.strict_period_secs))
            .finish()
            .ok_or_else(|| eyre!("strict governor requires non-zero burst_size and period"))?,
    );
    let issuer = Arc::new(
        GovernorConfigBuilder::default()
            .burst_size(config.strict_burst_size)
            .period(Duration::from_secs(config.strict_period_secs))
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .ok_or_else(|| eyre!("issuer governor requires non-zero burst_size and period"))?,
    );
    let permissive = Arc::new(
        GovernorConfigBuilder::default()
            .burst_size(config.permissive_burst_size)
            .period(Duration::from_secs(config.permissive_period_secs))
            .finish()
            .ok_or_else(|| eyre!("permissive governor requires non-zero burst_size and period"))?,
    );
    Ok((strict, issuer, permissive))
}

fn api_v1_routes(
    state: AppState,
    strict_governor: Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
    issuer_governor: Arc<GovernorConfig<SmartIpKeyExtractor, NoOpMiddleware>>,
    permissive_governor: Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
) -> Router<AppState> {
    let protected = Router::new()
        .nest(
            "/status-lists/{list_id}/statuses",
            Router::new()
                .route("/", put(publish_status))
                .route("/", patch(update_status)),
        )
        .route_layer(from_fn_with_state(state.clone(), auth))
        .layer(GovernorLayer::new(issuer_governor));

    let credentials = Router::new()
        .route("/credentials", post(credential_handler))
        .layer(GovernorLayer::new(strict_governor));

    let public_reads = Router::new()
        .route("/aggregation", get(get_aggregation))
        .route("/status-lists/{list_id}", get(get_status_list))
        .layer(GovernorLayer::new(permissive_governor));

    Router::new()
        .merge(protected)
        .merge(credentials)
        .merge(public_reads)
}

/// Axum middleware recording HTTP latency + request-count SLIs.
///
/// Keyed by the bounded route pattern (via [`MatchedPath`]), the HTTP method,
/// and the response status class. Runs after routing so `MatchedPath` is
/// populated, giving bounded cardinality regardless of path parameters.
async fn track_http_metrics(request: Request<Body>, next: Next) -> Response {
    let start = std::time::Instant::now();
    let method = request.method().clone();
    let matched = request.extensions().get::<MatchedPath>().cloned();
    let route: &str = matched
        .as_ref()
        .map(|p| p.as_str())
        .unwrap_or("unmatched");

    let response = next.run(request).await;

    let status_class = match response.status().as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "unknown",
    };
    crate::utils::metrics_http::record_request(
        method.as_str(),
        route,
        status_class,
        start.elapsed().as_secs_f64(),
    );

    response
}

fn attach_metrics(router: Router, config: &Config, registry: Registry) -> Router {
    if config.server.enable_metrics {
        tracing::info!("StatusList Monitor: ENABLED (Metrics at /metrics)");
        return router.route("/metrics", get(move || metrics_handler(registry)));
    } else {
        tracing::info!("StatusList Monitor: DISABLED");
    }
    router
}

/// Validates that the configured `aggregation_uri` (when set) has a path
/// matching the actual aggregation route registered on the router.
///
/// This prevents operators from shipping tokens with a dead `aggregation_uri`
/// member that points to a non-existent endpoint.
fn validate_aggregation_uri(config: &Config) -> color_eyre::Result<()> {
    let Some(uri) = config.server.aggregation_uri.as_deref() else {
        return Ok(());
    };
    let uri = uri.trim();
    if uri.is_empty() {
        return Ok(());
    }

    let parsed = reqwest::Url::parse(uri).wrap_err("Invalid aggregation_uri: not a valid URL")?;
    let path = parsed.path();
    if path != AGGREGATION_ROUTE_PATH {
        return Err(eyre!(
            "Configured aggregation_uri path '{path}' does not match the actual route '{AGGREGATION_ROUTE_PATH}'"
        ));
    }

    tracing::info!("aggregation_uri validated: {uri}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    #[test]
    fn test_validate_aggregation_uri_accepts_matching_path() {
        let config = Config::load_from_overrides(&[(
            "server.aggregation_uri",
            "https://statuslist.example.com/api/v1/aggregation",
        )])
        .unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[test]
    fn test_validate_aggregation_uri_rejects_mismatched_path() {
        let config = Config::load_from_overrides(&[(
            "server.aggregation_uri",
            "https://statuslist.example.com/statuslists/aggregation",
        )])
        .unwrap();
        let result = validate_aggregation_uri(&config);
        assert!(
            result.is_err(),
            "Should reject mismatched aggregation_uri path"
        );
    }

    #[test]
    fn test_validate_aggregation_uri_passes_when_unset() {
        let config = Config::load_from_overrides(&[]).unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[test]
    fn test_validate_aggregation_uri_rejects_invalid_url() {
        let config =
            Config::load_from_overrides(&[("server.aggregation_uri", "not a url")]).unwrap();
        let result = validate_aggregation_uri(&config);
        assert!(result.is_err(), "Should reject invalid URL");
    }
    #[tokio::test]
    async fn test_strict_governor_returns_429_when_burst_exceeded() {
        async fn handler() -> impl IntoResponse {
            "ok"
        }

        let strict = Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(2)
                .period(Duration::from_secs(600))
                .finish()
                .expect("non-zero burst/period"),
        );
        let permissive = Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(100)
                .period(Duration::from_secs(60))
                .finish()
                .expect("non-zero burst/period"),
        );

        let router = Router::new()
            .route("/write", post(handler))
            .layer(GovernorLayer::new(strict.clone()))
            .route("/read", axum::routing::get(handler))
            .layer(GovernorLayer::new(permissive.clone()))
            .with_state(());

        let make_request = |path: &'static str, method: Method| {
            Request::builder()
                .method(method)
                .uri(path)
                .extension(axum::extract::ConnectInfo(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    12345,
                )))
                .body(Body::empty())
                .unwrap()
        };

        let resp = router
            .clone()
            .oneshot(make_request("/write", Method::POST))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = router
            .clone()
            .oneshot(make_request("/write", Method::POST))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router
            .clone()
            .oneshot(make_request("/write", Method::POST))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_request_body_limit_returns_413_when_exceeded() {
        async fn handler() -> impl IntoResponse {
            "ok"
        }

        let router = Router::new()
            .route("/write", post(handler))
            .layer(RequestBodyLimitLayer::new(16))
            .with_state(());

        let oversized_body = "X".repeat(1024);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/write")
            .header("content-type", "text/plain")
            .header("content-length", oversized_body.len().to_string())
            .body(Body::from(oversized_body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_request_body_limit_allows_normal_body() {
        async fn handler() -> impl IntoResponse {
            "ok"
        }

        let router = Router::new()
            .route("/write", post(handler))
            .layer(RequestBodyLimitLayer::new(64))
            .with_state(());

        let request = Request::builder()
            .method(Method::POST)
            .uri("/write")
            .header("content-type", "text/plain")
            .header("content-length", "12")
            .body(Body::from("hello world!".to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_smart_ip_governor_independent_buckets_per_ip() {
        async fn handler() -> impl IntoResponse {
            "ok"
        }

        let governor = Arc::new(
            GovernorConfigBuilder::default()
                .burst_size(1)
                .period(Duration::from_secs(600))
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .expect("non-zero burst/period"),
        );

        let router = Router::new()
            .route("/write", axum::routing::put(handler))
            .layer(GovernorLayer::new(governor))
            .with_state(());

        fn make_request(ip: IpAddr) -> Request<Body> {
            Request::builder()
                .method(Method::PUT)
                .uri("/write")
                .extension(axum::extract::ConnectInfo(SocketAddr::new(ip, 12345)))
                .body(Body::empty())
                .unwrap()
        }

        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let resp = router.clone().oneshot(make_request(ip_a)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router.clone().oneshot(make_request(ip_b)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router.clone().oneshot(make_request(ip_a)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_connect_info_populated_for_real_http_requests() {
        use axum::extract::ConnectInfo;
        use reqwest::Client;

        async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
            addr.ip().to_string()
        }

        let router = Router::new().route("/info", get(handler));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let serve = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        );

        tokio::spawn(async move {
            serve.await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = Client::new();
        let resp = client
            .get(format!("http://{}/info", local_addr))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        let parsed: IpAddr = body.parse().unwrap();
        assert!(parsed.is_loopback());
    }

    /// The HTTP metrics layer must record the bounded route pattern (not the
    /// raw URI) and the status class for every request that passes through it.
    #[tokio::test]
    async fn http_metrics_middleware_records_route_and_status() {
        use crate::utils::metrics::{metrics_test_lock, setup_metrics};
        use opentelemetry_sdk::Resource;
        use prometheus::{Encoder, Registry, TextEncoder};

        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = crate::config::TelemetryConfig {
            environment: crate::config::TelemetryEnvironment::Development,
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
        drop(_metrics_guard);

        async fn ok_handler() -> impl IntoResponse {
            "ok"
        }
        async fn boom_handler() -> StatusCode {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        let router = Router::new()
            .route("/ok", get(ok_handler))
            .route("/boom", get(boom_handler))
            .layer(middleware::from_fn(track_http_metrics))
            .with_state(());

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/boom")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");

        assert!(
            body.contains(
                "http_server_requests_total{method=\"GET\",route=\"/ok\",status_class=\"2xx\""
            ),
            "expected 2xx counter for /ok; body:\n{body}"
        );
        assert!(
            body.contains(
                "http_server_requests_total{method=\"GET\",route=\"/boom\",status_class=\"5xx\""
            ),
            "expected 5xx counter for /boom; body:\n{body}"
        );
        assert!(
            body.contains("http_server_duration_seconds_count"),
            "expected duration histogram count; body:\n{body}"
        );
    }
}
