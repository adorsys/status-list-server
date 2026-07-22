use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post, put},
};
use color_eyre::eyre::{Context, eyre};
use governor::middleware::NoOpMiddleware;
use hyper::Method;
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

/// Path of the aggregation route, as registered under `/api/v1`.
const AGGREGATION_ROUTE_PATH: &str = "/api/v1/aggregation";

use crate::{
    config::Config,
    state::AppState,
    utils::metrics::{metrics_handler, setup_metrics, start_metrics_collector},
    web::{
        auth::auth,
        handlers::{
            credential_handler, get_aggregation, get_status_list, publish_status, update_status,
        },
    },
};

async fn welcome() -> impl IntoResponse {
    "Status list Server"
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

pub struct HttpServer {
    listener: TcpListener,
    router: Router,
}

impl HttpServer {
    pub async fn new(config: &Config, state: AppState) -> color_eyre::Result<Self> {
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
            .route("/health", get(health_check))
            .nest(
                "/api/v1",
                api_v1_routes(
                    state.clone(),
                    strict_governor.clone(),
                    issuer_governor.clone(),
                    permissive_governor.clone(),
                ),
            )
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors)
            .layer(RequestBodyLimitLayer::new(max_body_size))
            .layer(DefaultBodyLimit::disable())
            .with_state(state);

        router = attach_metrics(router, config);

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
        .await
        .wrap_err("Failed to start HTTP server")?;
        Ok(())
    }
}

/// Strict (credentials), per-issuer writes (IP-based via SmartIpKeyExtractor), and permissive (reads) governor configs.
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

/// Management API v1 routes with per-tier rate limiting and body-size bounds.
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

fn attach_metrics(router: Router, config: &Config) -> Router {
    if config.server.enable_metrics {
        match setup_metrics() {
            Ok(handle) => {
                start_metrics_collector();
                tracing::info!("StatusList Monitor: ENABLED (Metrics at /metrics)");
                return router.route("/metrics", get(move || metrics_handler(handle)));
            }
            Err(e) => tracing::warn!("Failed to setup metrics: {e}"),
        }
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
    use crate::config::Config;
    use sealed_test::prelude::*;

    use axum::{
        body::Body,
        extract::Request,
        http::{Method, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[sealed_test(env = [
        ("APP_SERVER__AGGREGATION_URI", "https://statuslist.example.com/api/v1/aggregation"),
    ])]
    fn test_validate_aggregation_uri_accepts_matching_path() {
        let config = Config::load().unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[sealed_test(env = [
        ("APP_SERVER__AGGREGATION_URI", "https://statuslist.example.com/statuslists/aggregation"),
    ])]
    fn test_validate_aggregation_uri_rejects_mismatched_path() {
        let config = Config::load().unwrap();
        let result = validate_aggregation_uri(&config);
        assert!(
            result.is_err(),
            "Should reject mismatched aggregation_uri path"
        );
    }

    #[sealed_test]
    fn test_validate_aggregation_uri_passes_when_unset() {
        // Ensure no leftover aggregation_uri from the environment.
        unsafe { std::env::remove_var("APP_SERVER__AGGREGATION_URI") };
        let config = Config::load().unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[sealed_test(env = [
        ("APP_SERVER__AGGREGATION_URI", "not a url"),
    ])]
    fn test_validate_aggregation_uri_rejects_invalid_url() {
        let config = Config::load().unwrap();
        let result = validate_aggregation_uri(&config);
        assert!(result.is_err(), "Should reject invalid URL");
    }

    /// Strict governor returns 429 after burst exhausted; permissive tiers unaffected (#171).
    #[tokio::test]
    async fn test_strict_governor_returns_429_when_burst_exceeded() {
        // Build a router with two tiers sharing the same per-IP key.  The
        // strict tier only allows 2 requests per 600 seconds, while the
        // permissive tier allows 100 requests per minute.
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

        // Two requests to the strict("/write") endpoint should succeed.
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

        // 3rd request to the strict endpoint should be rate-limited with 429.
        let resp = router
            .clone()
            .oneshot(make_request("/write", Method::POST))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // The permissive quota should still allow requests (#171
        // independent limits).
        let resp = router
            .clone()
            .oneshot(make_request("/read", Method::GET))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Oversized body returns 413 (#171).
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

    /// Normal-sized body passes through the limit layer (#171).
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

    /// SmartIpKeyExtractor governor: different IPs get independent rate-limit
    /// buckets; the same IP shares a bucket regardless of request metadata.
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

        // First request from ip_a succeeds.
        let resp = router.clone().oneshot(make_request(ip_a)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // First request from ip_b succeeds (different bucket).
        let resp = router.clone().oneshot(make_request(ip_b)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second request from ip_a is rate-limited (same bucket exhausted).
        let resp = router.clone().oneshot(make_request(ip_a)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// Integration test that boots a real HTTP server with
    /// into_make_service_with_connect_info and verifies that ConnectInfo is
    /// populated for real TCP connections.
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

        // Allow the server to start accepting connections.
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
}
