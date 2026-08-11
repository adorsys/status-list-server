use std::net::SocketAddr;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post, put},
};
use color_eyre::eyre::{Context, eyre};
use hyper::Method;
use prometheus::Registry;
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

const AGGREGATION_ROUTE_PATH: &str = "/api/v1/aggregation";

use crate::config::Config;
use crate::server::{
    AppState,
    auth::auth,
    handlers::{
        credential_handler, get_aggregation, get_status_list, publish_status, update_status,
    },
    rate_limit::runtime::{GovernorPolicies, RateLimitMetrics, RateLimitRuntime, governor_layer},
};
use crate::utils::metrics::metrics_handler;

async fn welcome() -> impl IntoResponse {
    "Status list Server"
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

pub struct HttpServer {
    listener: TcpListener,
    router: Router,
    rate_limit_runtime: RateLimitRuntime,
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

        // Startup diagnostics live here rather than in `Config::load`, which
        // runs before the tracing subscriber exists and would log into the void.
        report_config_diagnostics(config);

        let meter = opentelemetry::global::meter("status-list-server");
        let policies = GovernorPolicies::build(&config.rate_limit, &meter)?;
        let metrics = RateLimitMetrics::new(&meter);
        let rate_limit_runtime = policies.spawn_runtime(&config.rate_limit, &meter);

        let mut router = Router::new()
            .route("/", get(welcome))
            .route("/health", get(health_check))
            .nest("/api/v1", api_v1_routes(state.clone(), &policies, &metrics))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(crate::utils::telemetry::make_http_request_span),
            )
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

        Ok(Self {
            router,
            listener,
            rate_limit_runtime,
        })
    }

    pub async fn run(self) -> color_eyre::Result<()> {
        // Destructured rather than moved field-by-field so that
        // `rate_limit_runtime`  -  which owns the eviction tasks  -  stays alive
        // for exactly as long as the server is serving, and is torn down when
        // it stops.
        let Self {
            listener,
            router,
            rate_limit_runtime,
        } = self;

        tracing::info!("listening on {}", listener.local_addr()?);
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .wrap_err("Failed to start HTTP server");

        drop(rate_limit_runtime);
        result
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

fn api_v1_routes(
    state: AppState,
    policies: &GovernorPolicies,
    metrics: &RateLimitMetrics,
) -> Router<AppState> {
    // Layer order on the write routes, outermost first:
    //
    //   write_gate (client IP)  ->  auth  ->  issuer (verified issuer)  ->  handler
    //
    // The issuer tier MUST stay inside `auth`, which is what publishes the
    // verified issuer it keys on. If these two are ever swapped, the limiter
    // sees no verified issuer and fails key extraction  -  and the ordering is
    // pinned by `write_tier_is_keyed_on_the_verified_issuer` below.
    //
    // All three are `route_layer`s so they only run for requests that actually
    // match a write route; a 404 must not consume anyone's budget.
    let protected = Router::new()
        .nest(
            "/status-lists/{list_id}/statuses",
            Router::new()
                .route("/", put(publish_status))
                .route("/", patch(update_status)),
        )
        .route_layer(governor_layer(policies.issuer.clone(), "issuer", metrics))
        .route_layer(from_fn_with_state(state.clone(), auth))
        .route_layer(governor_layer(
            policies.write_gate.clone(),
            "write_gate",
            metrics,
        ));

    let credentials = Router::new()
        .route("/credentials", post(credential_handler))
        .route_layer(governor_layer(
            policies.credentials.clone(),
            "credentials",
            metrics,
        ));

    let public_reads = Router::new()
        .route("/aggregation", get(get_aggregation))
        .route("/status-lists/{list_id}", get(get_status_list))
        .route_layer(governor_layer(policies.reads.clone(), "reads", metrics));

    Router::new()
        .merge(protected)
        .merge(credentials)
        .merge(public_reads)
}

/// Reports configuration facts an operator needs to see at startup.
///
/// Deliberately not emitted from `Config::load`: configuration is read before
/// the tracing subscriber is installed, so anything logged there is discarded.
fn report_config_diagnostics(config: &Config) {
    if config.rate_limit.trusts_client_headers() {
        // WARN, not INFO: header-derived client IPs are only as trustworthy as
        // the proxy in front of this server. If that proxy does not overwrite
        // the header, clients choose their own rate-limit bucket.
        tracing::warn!(
            client_ip_source = %config
                .rate_limit
                .client_ip_source
                .expect("validated as set"),
            trusted_hops = config.rate_limit.trusted_hops,
            "rate limiter derives the client IP from a request header; this is safe only if \
             the proxy in front of this server overwrites that header on every request path"
        );
    }

    for (deprecated, current) in crate::config::deprecated_env_keys_in_use() {
        tracing::warn!(
            deprecated,
            current,
            "{deprecated} is deprecated and will be removed in a future release; use {current}"
        );
    }
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
        let config = Config::load_for_test(&[(
            "server.aggregation_uri",
            "https://statuslist.example.com/api/v1/aggregation",
        )])
        .unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[test]
    fn test_validate_aggregation_uri_rejects_mismatched_path() {
        let config = Config::load_for_test(&[(
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
        let config = Config::load_for_test(&[]).unwrap();
        assert!(validate_aggregation_uri(&config).is_ok());
    }

    #[test]
    fn test_validate_aggregation_uri_rejects_invalid_url() {
        let config = Config::load_for_test(&[("server.aggregation_uri", "not a url")]).unwrap();
        let result = validate_aggregation_uri(&config);
        assert!(result.is_err(), "Should reject invalid URL");
    }
    // -- rate limiting, exercised through the real `/api/v1` router ---------
    //
    // These tests build the same router the server serves, so they pin the
    // layer ordering and key derivation as they actually ship. Testing the key
    // extractors in isolation cannot do that: the bug this replaced was a
    // correct extractor wired into the wrong place.

    mod rate_limiting {
        use super::*;
        use crate::config::{ClientIpSource, RateLimitConfig};
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::test_utils::test_app_state;
        use axum::http::header;
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde::Serialize;
        use std::time::{SystemTime, UNIX_EPOCH};

        const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        const WRITE_PATH: &str = "/api/v1/status-lists/list-1/statuses";
        const READ_PATH: &str = "/api/v1/status-lists/list-1";
        fn test_meter() -> opentelemetry::metrics::Meter {
            opentelemetry::global::meter("status-list-server-test")
        }

        fn policies_for(config: &RateLimitConfig) -> GovernorPolicies {
            GovernorPolicies::build(config, &test_meter()).unwrap()
        }

        /// Builds the router with a meter the caller can read back, so that a
        /// test can assert on the counters the limiter emits.
        fn router_with_meter(
            state: AppState,
            policies: &GovernorPolicies,
            meter: &opentelemetry::metrics::Meter,
        ) -> Router {
            let metrics = RateLimitMetrics::new(meter);
            Router::new()
                .nest("/api/v1", api_v1_routes(state.clone(), policies, &metrics))
                .with_state(state)
        }

        fn router_for(state: AppState, policies: &GovernorPolicies) -> Router {
            router_with_meter(
                state,
                policies,
                &opentelemetry::global::meter("status-list-server-test"),
            )
        }

        /// `xff` entries become separate header lines, so that a client line
        /// followed by a proxy line is representable.
        fn req(method: Method, path: &str, xff: &[&str], bearer: Option<&str>) -> Request<Body> {
            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .extension(axum::extract::ConnectInfo(SocketAddr::new(PROXY, 45678)));
            for line in xff {
                builder = builder.header("x-forwarded-for", *line);
            }
            if let Some(token) = bearer {
                builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            builder.body(Body::empty()).unwrap()
        }

        const TEST_EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----";

        const TEST_PUBLIC_JWK: &str = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
            "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
        }"#;

        #[derive(Serialize)]
        struct TestClaims {
            iss: String,
            exp: usize,
        }

        fn signed_token(issuer: &str) -> String {
            let exp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize
                + 3600;
            let key = EncodingKey::from_ec_pem(TEST_EC_PRIVATE_PEM.as_bytes()).unwrap();
            encode(
                &Header::new(Algorithm::ES256),
                &TestClaims {
                    iss: issuer.to_string(),
                    exp,
                },
                &key,
            )
            .unwrap()
        }

        /// A syntactically valid JWT whose signature will not verify. This is
        /// what an attacker sends to try to choose their own bucket.
        fn forged_token(issuer: &str) -> String {
            let exp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize
                + 3600;
            let wrong_key = EncodingKey::from_secret(b"not-the-issuers-key");
            encode(
                &Header::new(Algorithm::HS256),
                &TestClaims {
                    iss: issuer.to_string(),
                    exp,
                },
                &wrong_key,
            )
            .unwrap()
        }

        async fn state_with_issuer(issuer: &str) -> AppState {
            let state = test_app_state(None).await;
            state
                .service
                .publish_credential(Credential {
                    issuer: Issuer(issuer.to_string()),
                    public_key: PublicJwk::try_new(TEST_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
                })
                .await
                .unwrap();
            state
        }

        /// AC: "a request carrying a spoofed `X-Forwarded-For` must land in the
        /// **same** bucket as one without."
        #[tokio::test]
        async fn spoofed_forwarded_for_shares_a_bucket_with_an_unspoofed_request() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            let first = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

            let second = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &["203.0.113.9"], None))
                .await
                .unwrap();
            assert_eq!(
                second.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "a spoofed X-Forwarded-For must not buy a fresh bucket"
            );
        }

        /// The memory-exhaustion half of the issue: rotating the header per
        /// request must not grow the limiter's key space.
        #[tokio::test]
        async fn rotating_forwarded_for_cannot_mint_buckets() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            for i in 0..25 {
                let spoof = format!("203.0.113.{i}");
                let _ = router
                    .clone()
                    .oneshot(req(Method::GET, READ_PATH, &[spoof.as_str()], None))
                    .await
                    .unwrap();
            }

            assert_eq!(
                policies.reads.limiter().len(),
                1,
                "25 distinct spoofed headers must still map to one bucket"
            );
        }

        /// Pins the layer ordering: the write tier keys on the issuer the auth
        /// middleware verified, so a second request from the same credential is
        /// throttled even though nothing about the transport changed.
        #[tokio::test]
        async fn write_tier_is_keyed_on_the_verified_issuer() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                1,
                100,
            ));
            let router = router_for(state, &policies);
            let token = signed_token("issuer-a");

            let first = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], Some(&token)))
                .await
                .unwrap();
            assert_ne!(
                first.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "the first authenticated write must pass the limiter"
            );
            assert_ne!(
                first.status(),
                StatusCode::UNAUTHORIZED,
                "the token should have verified"
            );
            assert_eq!(
                policies.issuer.limiter().len(),
                1,
                "a verified write should occupy exactly one issuer bucket"
            );

            let second = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], Some(&token)))
                .await
                .unwrap();
            assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        /// The regression this branch exists to prevent: an unverified `iss`
        /// claim must not select a bucket. If the issuer limiter were ever
        /// moved outside the auth middleware, each forged claim would allocate
        /// its own bucket and this assertion would fail.
        #[tokio::test]
        async fn forged_issuer_claims_cannot_mint_buckets() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                1,
                100,
            ));
            let router = router_for(state, &policies);

            for i in 0..25 {
                let token = forged_token(&format!("attacker-{i}"));
                let response = router
                    .clone()
                    .oneshot(req(Method::PUT, WRITE_PATH, &[], Some(&token)))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "a forged token must be rejected by auth"
                );
            }

            assert_eq!(
                policies.issuer.limiter().len(),
                0,
                "forged issuer claims must never reach the per-issuer limiter"
            );
        }

        /// Keying writes on a verified identity means auth  -  and a credential
        /// lookup  -  runs before the per-issuer limiter. The IP gate in front of
        /// auth is what stops anonymous traffic driving that lookup without
        /// limit.
        #[tokio::test]
        async fn unauthenticated_writes_are_gated_before_auth() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                100,
                2,
            ));
            let router = router_for(state, &policies);

            for _ in 0..2 {
                let response = router
                    .clone()
                    .oneshot(req(Method::PUT, WRITE_PATH, &[], None))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }

            let third = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], None))
                .await
                .unwrap();
            assert_eq!(
                third.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "anonymous write traffic must be gated in front of the auth middleware"
            );
        }

        /// `PATCH` shares the write routes' limiters with `PUT`, so the two
        /// must draw on one per-issuer budget rather than a budget each.
        #[tokio::test]
        async fn patch_and_put_share_the_issuer_budget() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                1,
                100,
            ));
            let router = router_for(state, &policies);
            let token = signed_token("issuer-a");

            let put = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], Some(&token)))
                .await
                .unwrap();
            assert_ne!(put.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_ne!(put.status(), StatusCode::UNAUTHORIZED);

            let patch = router
                .clone()
                .oneshot(req(Method::PATCH, WRITE_PATH, &[], Some(&token)))
                .await
                .unwrap();
            assert_eq!(
                patch.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "PATCH must spend the same budget PUT already exhausted"
            );
            assert_eq!(policies.issuer.limiter().len(), 1);
        }

        /// Credential registration has its own tier, keyed on the client IP and
        /// budgeted separately from every other route.
        #[tokio::test]
        async fn the_credentials_tier_limits_registration_independently() {
            let state = test_app_state(None).await;
            let mut config = RateLimitConfig::for_test(ClientIpSource::ConnectInfo, 0, 100, 100);
            config.credentials_burst_size = 1;
            let policies = policies_for(&config);
            let router = router_for(state, &policies);

            let first = router
                .clone()
                .oneshot(req(Method::POST, "/api/v1/credentials", &[], None))
                .await
                .unwrap();
            assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

            let second = router
                .clone()
                .oneshot(req(Method::POST, "/api/v1/credentials", &[], None))
                .await
                .unwrap();
            assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

            // The other tiers are untouched by registration traffic.
            assert_eq!(policies.credentials.limiter().len(), 1);
            assert_eq!(policies.reads.limiter().len(), 0);
            assert_eq!(policies.write_gate.limiter().len(), 0);

            let read = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            assert_ne!(
                read.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "exhausting the credentials tier must not throttle reads"
            );
        }

        /// The `x_real_ip` source, wired through the real router rather than
        /// only unit-tested: the proxy's value is the last occurrence, and a
        /// client-supplied one ahead of it must not select a different bucket.
        #[tokio::test]
        async fn x_real_ip_source_keys_on_the_proxy_supplied_value() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::XRealIp,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            let with_client_value = Request::builder()
                .method(Method::GET)
                .uri(READ_PATH)
                .header("x-real-ip", "9.9.9.9") // client-supplied, arrives first
                .header("x-real-ip", "203.0.113.7") // proxy-supplied
                .extension(axum::extract::ConnectInfo(SocketAddr::new(PROXY, 45678)))
                .body(Body::empty())
                .unwrap();
            let first = router.clone().oneshot(with_client_value).await.unwrap();
            assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

            let different_client_value = Request::builder()
                .method(Method::GET)
                .uri(READ_PATH)
                .header("x-real-ip", "8.8.8.8")
                .header("x-real-ip", "203.0.113.7")
                .extension(axum::extract::ConnectInfo(SocketAddr::new(PROXY, 45678)))
                .body(Body::empty())
                .unwrap();
            let second = router
                .clone()
                .oneshot(different_client_value)
                .await
                .unwrap();
            assert_eq!(
                second.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "changing the client-supplied X-Real-IP must not buy a fresh bucket"
            );
            assert_eq!(policies.reads.limiter().len(), 1);
        }

        /// A method that no handler accepts on an existing path still matched a
        /// route, so it does spend budget. Pinned deliberately: it means a
        /// client cannot probe methods for free, and it is the counterpart to
        /// `unmatched_paths_do_not_consume_budget`, where nothing matched at all.
        #[tokio::test]
        async fn a_wrong_method_on_a_real_path_consumes_budget() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            let wrong_method = router
                .clone()
                .oneshot(req(Method::DELETE, READ_PATH, &[], None))
                .await
                .unwrap();
            assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

            let read = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            assert_eq!(
                read.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "a 405 on a matching path spends the same budget a 200 would"
            );
        }

        /// With `rightmost_x_forwarded_for`, only entries at or right of the
        /// trust boundary may influence the key.
        #[tokio::test]
        async fn rightmost_forwarded_for_ignores_client_supplied_entries() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::RightmostXForwardedFor,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            // Client sends its own header line; the proxy appends its own.
            let first = router
                .clone()
                .oneshot(req(
                    Method::GET,
                    READ_PATH,
                    &["9.9.9.9", "203.0.113.7, 10.0.0.1"],
                    None,
                ))
                .await
                .unwrap();
            assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

            let second = router
                .clone()
                .oneshot(req(
                    Method::GET,
                    READ_PATH,
                    &["8.8.8.8", "203.0.113.7, 10.0.0.1"],
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(
                second.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "changing the client-supplied entry must not change the bucket"
            );
        }

        /// A path that matches no route must not consume anyone's budget  -
        /// otherwise unroutable traffic could exhaust a victim's bucket.
        #[tokio::test]
        async fn unmatched_paths_do_not_consume_budget() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            for _ in 0..5 {
                let response = router
                    .clone()
                    .oneshot(req(Method::GET, "/api/v1/does-not-exist", &[], None))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }

            let real = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            assert_ne!(real.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        /// The 429 contract: JSON in the same shape as the rest of the API,
        /// plus the headers a client needs in order to back off.
        #[tokio::test]
        async fn rejection_is_json_and_carries_backoff_headers() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            let _ = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            let rejected = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();

            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                rejected
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json")
            );
            assert!(
                rejected.headers().contains_key("retry-after"),
                "clients need retry-after to back off correctly"
            );
            assert!(
                rejected.headers().contains_key("x-ratelimit-limit"),
                "expected the x-ratelimit-* set from use_headers()"
            );

            let body = axum::body::to_bytes(rejected.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "rate_limited");
            // Naming the tier is what lets a caller distinguish "you personally
            // are writing too fast" from "this source IP is". Without it, an
            // ordering regression that swapped the tiers would be invisible
            // here, since both return 429.
            assert!(
                json["error_description"]
                    .as_str()
                    .is_some_and(|d| d.contains("reads")),
                "rejection should name the tier that rejected it, got {json}"
            );
        }

        /// The write routes carry two limiters, and `StateInformationMiddleware`
        /// merges its headers with `HeaderMap::extend`, which *appends*. If both
        /// tiers reported, every write response would carry two
        /// `x-ratelimit-limit` values describing different budgets — invalid per
        /// the OpenAPI, and ambiguous for any client that reads them.
        #[tokio::test]
        async fn a_write_response_reports_exactly_one_rate_limit_budget() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                7,
                100,
            ));
            let router = router_for(state, &policies);

            let response = router
                .clone()
                .oneshot(req(
                    Method::PUT,
                    WRITE_PATH,
                    &[],
                    Some(&signed_token("issuer-a")),
                ))
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::UNAUTHORIZED);

            for header_name in ["x-ratelimit-limit", "x-ratelimit-remaining"] {
                let values: Vec<_> = response.headers().get_all(header_name).iter().collect();
                assert_eq!(
                    values.len(),
                    1,
                    "expected exactly one {header_name}, got {values:?}"
                );
            }
            assert_eq!(
                response
                    .headers()
                    .get("x-ratelimit-limit")
                    .and_then(|v| v.to_str().ok()),
                Some("7"),
                "the reported budget must be the issuer tier's, not the IP gate's"
            );
        }

        /// A request with no connection info cannot be keyed. The limiter must
        /// refuse it rather than let it through unmetered, and say so in a way
        /// that is clearly a server fault.
        #[tokio::test]
        async fn a_request_that_cannot_be_keyed_is_refused() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                10,
            ));
            let router = router_for(state, &policies);

            // Deliberately built without the ConnectInfo extension.
            let request = Request::builder()
                .method(Method::GET)
                .uri(READ_PATH)
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "rate_limit_unavailable");
            assert_eq!(
                policies.reads.limiter().len(),
                0,
                "a request that could not be keyed must not create a bucket"
            );
        }

        /// Limiter responses are per-caller and per-instant; a shared cache
        /// storing one would serve a 429 to an unthrottled client.
        #[tokio::test]
        async fn rejections_are_not_cacheable() {
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_for(state, &policies);

            let _ = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();
            let rejected = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &[], None))
                .await
                .unwrap();

            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                rejected
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store")
            );
        }

        /// The write routes carry two limiters. A rejection must say which one
        /// fired, and it must be the IP gate for unauthenticated traffic.
        #[tokio::test]
        async fn rejection_names_the_tier_that_fired() {
            let state = state_with_issuer("issuer-a").await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                100,
                1,
            ));
            let router = router_for(state, &policies);

            let _ = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], None))
                .await
                .unwrap();
            let rejected = router
                .clone()
                .oneshot(req(Method::PUT, WRITE_PATH, &[], None))
                .await
                .unwrap();

            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            let body = axum::body::to_bytes(rejected.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                json["error_description"]
                    .as_str()
                    .is_some_and(|d| d.contains("write_gate")),
                "unauthenticated writes should be rejected by the IP gate, got {json}"
            );
        }

        /// A meter backed by a registry the test can read back, so counter
        /// assertions do not race other tests through the OpenTelemetry global.
        fn local_meter() -> (prometheus::Registry, opentelemetry::metrics::Meter) {
            use opentelemetry::metrics::MeterProvider as _;

            let registry = prometheus::Registry::new();
            let exporter = opentelemetry_prometheus::exporter()
                .with_registry(registry.clone())
                .build()
                .unwrap();
            let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_reader(exporter)
                .build();
            let meter = provider.meter("rate-limit-test");
            // The provider must outlive the meter for the reader to stay
            // attached; leaking it is confined to the test process.
            std::mem::forget(provider);
            (registry, meter)
        }

        fn counter_total(registry: &prometheus::Registry, name: &str) -> f64 {
            registry
                .gather()
                .into_iter()
                .filter(|family| family.name().starts_with(name))
                .flat_map(|family| family.get_metric().to_vec())
                .map(|metric| metric.get_counter().value())
                .sum()
        }

        /// A misconfigured `client_ip_source` is invisible in responses — the
        /// limiter just keys more coarsely. This counter is the only signal, so
        /// it has to actually move.
        #[tokio::test]
        async fn falling_back_to_the_peer_address_is_counted() {
            let (registry, meter) = local_meter();
            let state = test_app_state(None).await;
            // Configured for XFF, but the requests below carry none.
            let policies = GovernorPolicies::build(
                &RateLimitConfig::for_test(ClientIpSource::RightmostXForwardedFor, 0, 10, 100),
                &meter,
            )
            .unwrap();
            let router = router_with_meter(state, &policies, &meter);

            for _ in 0..3 {
                let _ = router
                    .clone()
                    .oneshot(req(Method::GET, READ_PATH, &[], None))
                    .await
                    .unwrap();
            }

            assert_eq!(
                counter_total(&registry, "rate_limit_ip_source_fallback"),
                3.0,
                "every request without the configured header should be counted"
            );
        }

        /// With the header present and well-formed, nothing falls back.
        #[tokio::test]
        async fn a_usable_forwarded_header_records_no_fallback() {
            let (registry, meter) = local_meter();
            let state = test_app_state(None).await;
            let policies = GovernorPolicies::build(
                &RateLimitConfig::for_test(ClientIpSource::RightmostXForwardedFor, 0, 10, 100),
                &meter,
            )
            .unwrap();
            let router = router_with_meter(state, &policies, &meter);

            let _ = router
                .clone()
                .oneshot(req(Method::GET, READ_PATH, &["203.0.113.7"], None))
                .await
                .unwrap();

            assert_eq!(
                counter_total(&registry, "rate_limit_ip_source_fallback"),
                0.0
            );
        }

        /// The limiter's counters are the only signal an operator gets that it
        /// is doing anything.
        #[tokio::test]
        async fn rejections_increment_the_rate_limit_counter() {
            let (registry, meter) = local_meter();
            let state = test_app_state(None).await;
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                10,
                1,
            ));
            let router = router_with_meter(state, &policies, &meter);

            for _ in 0..3 {
                let _ = router
                    .clone()
                    .oneshot(req(Method::GET, READ_PATH, &[], None))
                    .await
                    .unwrap();
            }

            assert_eq!(
                counter_total(&registry, "rate_limit_rejected"),
                2.0,
                "burst of 1 followed by 3 requests should record 2 rejections"
            );
        }

        /// Distinct issuers must not share a budget.
        #[tokio::test]
        async fn distinct_issuers_get_independent_buckets() {
            let state = test_app_state(None).await;
            for issuer in ["issuer-a", "issuer-b"] {
                state
                    .service
                    .publish_credential(Credential {
                        issuer: Issuer(issuer.to_string()),
                        public_key: PublicJwk::try_new(TEST_PUBLIC_JWK.as_bytes().to_vec())
                            .unwrap(),
                    })
                    .await
                    .unwrap();
            }
            let policies = policies_for(&RateLimitConfig::for_test(
                ClientIpSource::ConnectInfo,
                0,
                1,
                100,
            ));
            let router = router_for(state, &policies);

            for issuer in ["issuer-a", "issuer-b"] {
                let response = router
                    .clone()
                    .oneshot(req(
                        Method::PUT,
                        WRITE_PATH,
                        &[],
                        Some(&signed_token(issuer)),
                    ))
                    .await
                    .unwrap();
                assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            }

            let repeat = router
                .clone()
                .oneshot(req(
                    Method::PUT,
                    WRITE_PATH,
                    &[],
                    Some(&signed_token("issuer-a")),
                ))
                .await
                .unwrap();
            assert_eq!(repeat.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(policies.issuer.limiter().len(), 2);
        }
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
}
