use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Router,
    body::Body,
    extract::{DefaultBodyLimit, MatchedPath},
    http::Request,
    middleware::{self, Next, from_fn_with_state},
    response::Response,
    routing::{get, patch, post, put},
};
use color_eyre::eyre::{Context, eyre};
use governor::{Quota, middleware::NoOpMiddleware};
use hyper::Method;
use prometheus::Registry;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_governor::{
    GovernorLayer,
    governor::{GovernorConfig, GovernorConfigBuilder},
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::config::{API_V1_PREFIX, Config};

use crate::server::handlers::{
    allocate_indices_route, get_aggregation, get_credential, get_issuer_aggregation,
    get_status_list, publish_status_route, update_status_route,
};
use crate::server::rate_limit::{
    AuthFailureGate, ClientAddress, ClientKeyExtractor, auth_failure_gate, governor_error_response,
    issuer_rate_limit, spawn_governor_pruner,
};
use crate::server::{AppState, auth::auth, health, service_document};
use crate::utils::metrics::metrics_handler;

#[derive(Clone)]
struct ListenerName(&'static str);

struct ListenerServer {
    listener: TcpListener,
    /// Captured at bind time so reading it later can't fail.
    local_addr: SocketAddr,
    router: Router,
}

pub struct HttpServer {
    public: ListenerServer,
    management: ListenerServer,
    admin: ListenerServer,
}

impl HttpServer {
    pub async fn new(
        config: &Config,
        state: AppState,
        prometheus_registry: Registry,
    ) -> color_eyre::Result<Self> {
        let (auth_gate, permissive_governor, admin_governor) =
            build_governor_configs(&config.rate_limit)?;
        AuthFailureGate::spawn_pruner(&auth_gate);
        spawn_governor_pruner(permissive_governor.limiter(), "public");
        spawn_governor_pruner(admin_governor.limiter(), "admin");

        let public_router = with_listener_name(
            with_common_layers(
                public_routes(permissive_governor)
                    // Public only: admin and management have no browser clients,
                    // and no web page should be able to read /metrics on a dev machine.
                    .layer(
                        CorsLayer::new()
                            .allow_methods([Method::GET, Method::OPTIONS])
                            .allow_origin(Any)
                            .allow_headers(Any),
                    ),
                config,
            ),
            "public",
        )
        .with_state(state.clone());

        let management_router = with_listener_name(
            with_common_layers(management_routes(state.clone(), auth_gate), config),
            "management",
        )
        .with_state(state.clone());

        let admin_router = with_listener_name(
            with_common_layers(
                admin_routes(state.clone(), config, prometheus_registry, admin_governor),
                config,
            ),
            "admin",
        )
        .with_state(state);

        let public_listener =
            bind_listener(&config.server.host, config.server.port, "public").await?;
        let management_listener = bind_listener(
            &config.server.management.host,
            config.server.management.port,
            "management",
        )
        .await?;
        let admin_listener =
            bind_listener(&config.server.admin.host, config.server.admin.port, "admin").await?;

        let public_addr = public_listener
            .local_addr()
            .wrap_err("failed to read public listener address")?;
        let management_addr = management_listener
            .local_addr()
            .wrap_err("failed to read management listener address")?;
        let admin_addr = admin_listener
            .local_addr()
            .wrap_err("failed to read admin listener address")?;

        Ok(Self {
            public: ListenerServer {
                listener: public_listener,
                local_addr: public_addr,
                router: public_router,
            },
            management: ListenerServer {
                listener: management_listener,
                local_addr: management_addr,
                router: management_router,
            },
            admin: ListenerServer {
                listener: admin_listener,
                local_addr: admin_addr,
                router: admin_router,
            },
        })
    }

    /// Serves all three listeners until `shutdown`, returning only once every one has drained.
    /// A listener error is returned, so the process exits non-zero.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> color_eyre::Result<()> {
        tokio::try_join!(
            serve(
                self.public.listener,
                self.public.router,
                "public",
                shutdown.clone(),
            ),
            serve(
                self.management.listener,
                self.management.router,
                "management",
                shutdown.clone(),
            ),
            serve(
                self.admin.listener,
                self.admin.router,
                "admin",
                shutdown.clone(),
            ),
        )?;
        Ok(())
    }

    /// Broadcasts SIGINT/SIGTERM as the shutdown signal.
    /// Kept apart from `run` so tests can drive shutdown through the channel.
    pub fn install_shutdown_handler(shutdown: &watch::Sender<bool>) {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown.send(true);
        });
    }

    pub fn public_addr(&self) -> SocketAddr {
        self.public.local_addr
    }

    pub fn admin_addr(&self) -> SocketAddr {
        self.admin.local_addr
    }

    pub fn management_addr(&self) -> SocketAddr {
        self.management.local_addr
    }
}

async fn bind_listener(host: &str, port: u16, name: &str) -> color_eyre::Result<TcpListener> {
    TcpListener::bind(format!("{host}:{port}"))
        .await
        .wrap_err_with(|| format!("Failed to bind {name} listener to {host}:{port}"))
}

async fn serve(
    listener: TcpListener,
    router: Router,
    name: &str,
    mut shutdown: watch::Receiver<bool>,
) -> color_eyre::Result<()> {
    match listener.local_addr() {
        Ok(addr) => tracing::info!(listener = name, %addr, "listening"),
        Err(_) => tracing::info!(listener = name, "listening"),
    }
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    // `wait_for` sees a signal sent before it was polled; `Notify::notify_waiters` would lose it.
    .with_graceful_shutdown(async move {
        let _ = shutdown.wait_for(|shutdown| *shutdown).await;
    })
    .await
    .map_err(|e| eyre!("HTTP server ({name}) failed: {e}"))
}

/// Shared by every listener; CORS is added to the public router only.
fn with_common_layers(router: Router<AppState>, config: &Config) -> Router<AppState> {
    router
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(crate::utils::telemetry::make_http_request_span),
        )
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn(track_http_metrics))
        .layer(RequestBodyLimitLayer::new(
            config.limits.max_body_size_bytes,
        ))
        .layer(DefaultBodyLimit::disable())
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

type ClientGovernor = Arc<GovernorConfig<ClientKeyExtractor, NoOpMiddleware>>;

type GovernorPolicies = (Arc<AuthFailureGate>, ClientGovernor, ClientGovernor);

fn build_governor_configs(
    config: &crate::config::RateLimitConfig,
) -> color_eyre::Result<GovernorPolicies> {
    let admission = NonZeroU32::new(config.admission_per_second)
        .zip(NonZeroU32::new(config.admission_burst_size))
        .map(|(rate, burst)| Quota::per_second(rate).allow_burst(burst))
        .ok_or_else(|| eyre!("management admission requires non-zero burst_size and per_second"))?;
    let failures = Quota::with_period(Duration::from_secs(config.strict_period_secs))
        .zip(NonZeroU32::new(config.strict_burst_size))
        .map(|(quota, burst)| quota.allow_burst(burst))
        .ok_or_else(|| {
            eyre!("management authentication gate requires non-zero burst_size and period")
        })?;
    let client = Arc::new(ClientAddress::new(
        config.resolved_client_ip_source(),
        config.trusted_proxy_networks()?,
    ));
    let auth_gate = Arc::new(AuthFailureGate::new(admission, failures, client.clone()));
    let permissive_period = Duration::try_from_secs_f64(config.permissive_period_secs)
        .wrap_err("rate_limit.permissive_period_secs is not a valid duration")?;
    let permissive = Arc::new(
        GovernorConfigBuilder::default()
            .burst_size(config.permissive_burst_size)
            .period(permissive_period)
            .key_extractor(ClientKeyExtractor(client.clone()))
            .finish()
            .ok_or_else(|| eyre!("permissive governor requires non-zero burst_size and period"))?,
    );
    let admin = Arc::new(
        GovernorConfigBuilder::default()
            .burst_size(config.permissive_burst_size)
            .period(permissive_period)
            .key_extractor(ClientKeyExtractor(client))
            .finish()
            .ok_or_else(|| eyre!("admin governor requires non-zero burst_size and period"))?,
    );
    Ok((auth_gate, permissive, admin))
}

/// Internet-facing: never register management or admin routes here.
fn public_routes(permissive_governor: ClientGovernor) -> Router<AppState> {
    let public_reads = Router::new()
        .route("/aggregation", get(get_aggregation))
        .route("/aggregation/{aggregation_id}", get(get_issuer_aggregation))
        .route("/status-lists/{list_id}", get(get_status_list))
        .layer(GovernorLayer::new(permissive_governor).error_handler(governor_error_response));

    Router::new()
        .route("/", get(service_document))
        .route("/health", get(health::live))
        .route("/health/live", get(health::live))
        .nest(API_V1_PREFIX, public_reads)
}

/// Routes owned by the management listener: authenticated issuer operations.
fn management_routes(state: AppState, auth_gate: Arc<AuthFailureGate>) -> Router<AppState> {
    // Order: authentication gate -> auth -> issuer limiter -> handler. The gate
    // admits a coarse per-address budget before `auth` does any work. Only a
    // verified identity reaches an issuer bucket, and only rejected
    // authentications spend the gate's failure budget. Every authenticated route
    // spends the issuer's bucket, so no route lets one issuer load the server
    // unbounded.
    let protected = Router::new()
        .nest(
            "/status-lists/{list_id}/statuses",
            Router::new()
                .route("/", put(publish_status_route))
                .route("/", patch(update_status_route)),
        )
        .route(
            "/status-lists/{list_id}/allocations",
            post(allocate_indices_route),
        )
        .route("/credentials", get(get_credential))
        .route_layer(from_fn_with_state(state.clone(), issuer_rate_limit))
        .route_layer(from_fn_with_state(state.clone(), auth))
        .route_layer(from_fn_with_state(auth_gate, auth_failure_gate));

    Router::new().nest(API_V1_PREFIX, protected)
}

/// Routes owned by the admin listener: readiness, metrics, and authenticated issuer reads.
/// Management and public routes are deliberately absent, so probing the admin
/// port with anything else returns a structural 404.
fn admin_routes(
    state: AppState,
    config: &Config,
    registry: Registry,
    admin_governor: ClientGovernor,
) -> Router<AppState> {
    let admin_api = Router::new()
        .route(
            "/issuers",
            get(crate::server::handlers::admin::list_issuers),
        )
        .route(
            "/issuers/{issuer_id}",
            get(crate::server::handlers::admin::get_issuer),
        )
        .layer(GovernorLayer::new(admin_governor).error_handler(governor_error_response));
    let router = Router::new()
        .route("/health/ready", get(health::ready))
        .nest(
            "/admin/v1",
            admin_api.route_layer(from_fn_with_state(state, crate::server::auth::admin_auth)),
        );
    attach_metrics(router, config, registry)
}

/// Must stay outside CatchPanicLayer so panics still count as 5xx.
/// Health and metrics routes are skipped so probes don't skew the error-rate SLI.
async fn track_http_metrics(request: Request<Body>, next: Next) -> Response {
    let start = std::time::Instant::now();
    let method = request.method().clone();
    let matched = request.extensions().get::<MatchedPath>().cloned();
    let route: &str = matched.as_ref().map(|p| p.as_str()).unwrap_or("unmatched");
    // Falls back to "unknown" (routers built in tests) instead of dropping the metric.
    let listener_name: &'static str = request
        .extensions()
        .get::<ListenerName>()
        .map(|l| l.0)
        .unwrap_or("unknown");

    if matches!(
        route,
        "/health" | "/health/live" | "/health/ready" | "/metrics"
    ) {
        return next.run(request).await;
    }

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
        listener_name,
        start.elapsed().as_secs_f64(),
    );

    response
}

/// Must wrap `with_common_layers`, not sit inside it,
/// or the metrics middleware runs first and labels everything "unknown".
fn with_listener_name<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    name: &'static str,
) -> Router<S> {
    router.layer(Extension(ListenerName(name)))
}

fn attach_metrics<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    config: &Config,
    registry: Registry,
) -> Router<S> {
    if config.server.enable_metrics {
        tracing::info!("StatusList Monitor: ENABLED (Metrics at /metrics)");
        return router.route("/metrics", get(move || metrics_handler(registry)));
    } else {
        tracing::info!("StatusList Monitor: DISABLED");
    }
    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    /// Credential lookup lives on the management listener, while aggregation
    /// reads live on the public listener; each keeps its own
    /// layers (auth, permissive governor) once built as separate routers.
    #[tokio::test]
    async fn test_management_rejects_registration_and_public_serves_aggregation() {
        let config = Config::load_from_overrides(&[]).unwrap();
        let (auth_gate, permissive, _) = build_governor_configs(&config.rate_limit).unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        let aggregation_id = crate::test_utils::register_issuer(&state.service, "issuer1").await;
        let management = management_routes(state.clone(), auth_gate).with_state(state.clone());
        let public = public_routes(permissive).with_state(state);
        let send = |router: Router, method: Method, uri: String, body: String| {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .extension(axum::extract::ConnectInfo(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    12345,
                )))
                .body(Body::from(body))
                .unwrap();
            router.clone().oneshot(request)
        };

        let registration = send(
            management.clone(),
            Method::POST,
            format!("{API_V1_PREFIX}/credentials"),
            format!(
                r#"{{"issuer":"issuer1","public_key":{}}}"#,
                crate::test_fixtures::TEST_EC_PUBLIC_JWK
            ),
        )
        .await
        .unwrap();
        // No POST handler is registered on this path; it must never accept an
        // unauthenticated registration.
        assert_eq!(registration.status(), StatusCode::UNAUTHORIZED);

        let unauthenticated = send(
            management,
            Method::GET,
            format!("{API_V1_PREFIX}/credentials"),
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let aggregation = send(
            public,
            Method::GET,
            format!("{API_V1_PREFIX}/aggregation/{aggregation_id}"),
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(aggregation.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_routes_404_on_the_wrong_listener() {
        use crate::test_utils::{publish_list, register_issuer};

        let config = Config::load_from_overrides(&[
            // Enable metrics so /metrics is a real route on admin, not a
            // universal 404 from a missing route.
            ("APP_SERVER__ENABLE_METRICS", "true"),
        ])
        .unwrap();
        let (auth_gate, permissive, admin_governor) =
            build_governor_configs(&config.rate_limit).unwrap();

        let state = crate::test_utils::test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        let list_id = uuid::Uuid::new_v4().to_string();
        publish_list(&state.service, "issuer1", &list_id).await;

        let public = public_routes(permissive).with_state(state.clone());
        let management = management_routes(state.clone(), auth_gate).with_state(state.clone());
        let admin = admin_routes(
            state.clone(),
            &config,
            prometheus::Registry::new(),
            admin_governor,
        )
        .with_state(state);

        let status = |router: Router, method: Method, uri: &str| {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .extension(axum::extract::ConnectInfo(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    12345,
                )))
                .body(Body::empty())
                .unwrap();
            router.clone().oneshot(request)
        };

        const PUBLIC: &str = "public";
        const MANAGEMENT: &str = "management";
        const ADMIN: &str = "admin";

        let routes: &[(Method, &str, &str)] = &[
            (
                Method::GET,
                &format!("{API_V1_PREFIX}/status-lists/{list_id}"),
                PUBLIC,
            ),
            (
                Method::GET,
                &format!("{API_V1_PREFIX}/aggregation/{aggregation_id}"),
                PUBLIC,
            ),
            (Method::GET, &format!("{API_V1_PREFIX}/aggregation"), PUBLIC),
            (Method::GET, "/", PUBLIC),
            (Method::GET, "/health", PUBLIC),
            (Method::GET, "/health/live", PUBLIC),
            (
                Method::PUT,
                &format!("{API_V1_PREFIX}/status-lists/{list_id}/statuses"),
                MANAGEMENT,
            ),
            (
                Method::PATCH,
                &format!("{API_V1_PREFIX}/status-lists/{list_id}/statuses"),
                MANAGEMENT,
            ),
            (
                Method::POST,
                &format!("{API_V1_PREFIX}/status-lists/{list_id}/allocations"),
                MANAGEMENT,
            ),
            (
                Method::GET,
                &format!("{API_V1_PREFIX}/credentials"),
                MANAGEMENT,
            ),
            (Method::GET, "/health/ready", ADMIN),
            (Method::GET, "/metrics", ADMIN),
            (Method::GET, "/admin/v1/issuers", ADMIN),
            (Method::GET, "/admin/v1/issuers/example", ADMIN),
        ];

        for (method, path, owner) in routes {
            let routers = [
                (PUBLIC, public.clone()),
                (MANAGEMENT, management.clone()),
                (ADMIN, admin.clone()),
            ];
            for (listener_name, router) in &routers {
                let resp = status(router.clone(), method.clone(), path).await.unwrap();
                if listener_name == owner {
                    assert_ne!(
                        resp.status(),
                        StatusCode::NOT_FOUND,
                        "{method} {path} must NOT return 404 on its owner ({owner}), got {}",
                        resp.status()
                    );
                } else {
                    assert_eq!(
                        resp.status(),
                        StatusCode::NOT_FOUND,
                        "{method} {path} must return 404 on {listener_name} (owned by {owner})"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn test_root_returns_json_service_document() {
        use axum::body::to_bytes;

        let config = Config::load_from_overrides(&[]).unwrap();
        let (_, permissive, _) = build_governor_configs(&config.rate_limit).unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        let public = public_routes(permissive).with_state(state);

        let resp = public
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.starts_with("application/json"),
            "expected application/json Content-Type, got {content_type:?}"
        );
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["service"], "Status List Server");
        assert_eq!(doc["links"]["documentation"], crate::config::REPOSITORY_URL);
        assert!(doc["links"]["portal"].as_str().is_none());
        assert!(doc.get("version").is_none());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_aggregation_never_answers_in_part_when_the_quota_is_disabled_live() {
        use crate::domain::models::status_list::AGGREGATION_DEFAULT_LIMIT;
        use crate::outbound::sql::list_quota;
        use crate::test_utils::{publish_list, register_issuer, sqlite_test_db, test_app_state};
        use axum::body::to_bytes;
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let db = sqlite_test_db(None).await;
        list_quota::enable(&db, AGGREGATION_DEFAULT_LIMIT as u64)
            .await
            .unwrap();
        let mut state = test_app_state(Some(db.clone())).await;
        state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let config = Config::load_from_overrides(&[]).unwrap();
        let (_, permissive, _) = build_governor_configs(&config.rate_limit).unwrap();
        let router = public_routes(permissive).with_state(state.clone());
        let get = |uri: String| {
            let request = Request::get(uri)
                .extension(axum::extract::ConnectInfo(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    12345,
                )))
                .body(Body::empty())
                .unwrap();
            router.clone().oneshot(request)
        };
        let advertised = |token: Vec<u8>| {
            let token = String::from_utf8(token).unwrap();
            let payload = URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap();
            let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            claims["status_list"]["aggregation_uri"].is_string()
        };
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        let list_id = uuid::Uuid::new_v4().to_string();
        publish_list(&state.service, "issuer1", &list_id).await;
        let token = get(format!("{API_V1_PREFIX}/status-lists/{list_id}"))
            .await
            .unwrap();
        let token = to_bytes(token.into_body(), usize::MAX).await.unwrap();
        assert!(advertised(token.to_vec()));

        list_quota::disable(&db).await.unwrap();
        for _ in 0..AGGREGATION_DEFAULT_LIMIT {
            publish_list(&state.service, "issuer1", &uuid::Uuid::new_v4().to_string()).await;
        }
        let cached = get(format!("{API_V1_PREFIX}/status-lists/{list_id}"))
            .await
            .unwrap();
        let cached = to_bytes(cached.into_body(), usize::MAX).await.unwrap();
        assert!(
            advertised(cached.to_vec()),
            "the warm token still points there"
        );

        let unpaged = get(format!("{API_V1_PREFIX}/aggregation/{aggregation_id}"))
            .await
            .unwrap();
        assert_eq!(unpaged.status(), StatusCode::CONFLICT);

        let mut lists = 0;
        let mut next = Some(
            url::Url::parse(&format!(
                "http://localhost{API_V1_PREFIX}/aggregation/{aggregation_id}?limit={AGGREGATION_DEFAULT_LIMIT}"
            ))
            .unwrap(),
        );
        while let Some(url) = next {
            let page = get(url[url::Position::BeforePath..].to_string())
                .await
                .unwrap();
            assert_eq!(page.status(), StatusCode::OK, "{url}");
            next = page.headers().get(axum::http::header::LINK).map(|link| {
                let link = link.to_str().unwrap();
                let (target, _) = link.strip_prefix('<').unwrap().split_once('>').unwrap();
                url.join(target).unwrap()
            });
            let page: serde_json::Value =
                serde_json::from_slice(&to_bytes(page.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            lists += page["status_lists"].as_array().unwrap().len();
        }
        assert_eq!(
            lists,
            AGGREGATION_DEFAULT_LIMIT + 1,
            "paging still reaches every list"
        );
    }

    #[tokio::test]
    async fn test_graceful_shutdown_covers_all_three_listeners() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        async fn ephemeral_port() -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            port
        }
        let public_port = ephemeral_port().await;
        let management_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let config = Config::load_from_overrides(&[
            ("server.host", "127.0.0.1"),
            ("server.port", &public_port.to_string()),
            ("server.management.host", "127.0.0.1"),
            ("server.management.port", &management_port.to_string()),
            ("server.admin.host", "127.0.0.1"),
            ("server.admin.port", &admin_port.to_string()),
        ])
        .unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        let server = HttpServer::new(&config, state, prometheus::Registry::new())
            .await
            .unwrap();

        let public_addr = server.public_addr();
        let management_addr = server.management_addr();
        let admin_addr = server.admin_addr();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut run_handle = tokio::spawn(server.run(shutdown_rx));

        let client = reqwest::Client::new();
        let mut up = false;
        for _ in 0..50 {
            if client
                .get(format!("http://{public_addr}/health/live"))
                .send()
                .await
                .map(|r| r.status() == StatusCode::OK)
                .unwrap_or(false)
            {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(up, "public listener never became ready");

        let public_resp = client
            .get(format!("http://{public_addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(public_resp.status(), StatusCode::OK);
        let mgmt_resp = client
            .get(format!("http://{management_addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(mgmt_resp.status(), StatusCode::NOT_FOUND);
        let admin_resp = client
            .get(format!("http://{admin_addr}/health/ready"))
            .send()
            .await
            .unwrap();
        assert_eq!(admin_resp.status(), StatusCode::OK);

        // Hold a request in flight on the management listener: send the head
        // and only half of the body, so the handler is waiting on the rest.
        let mut slow = TcpStream::connect(management_addr).await.unwrap();
        slow.write_all(b"GET /api/v1/credentials HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        slow.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        shutdown_tx.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut run_handle)
                .await
                .is_err(),
            "run returned while a request was still in flight on the management listener"
        );

        // Finish the request: it must still be served despite shutdown.
        slow.write_all(b" localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut response))
            .await
            .expect("in-flight request was not answered during graceful shutdown")
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "in-flight request must complete normally, got: {response}"
        );

        tokio::time::timeout(Duration::from_secs(10), run_handle)
            .await
            .expect("run did not finish after the in-flight request completed")
            .unwrap()
            .expect("run must return Ok after graceful shutdown of all listeners");
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

    fn issuer_token(issuer: &str, kid: &str, private_pem: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("statuslist-management+jwt".to_string());
        header.kid = Some(kid.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": issuer, "iat": now, "exp": now + 300 }),
            &jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// Management routes over a registry holding `issuer-a` and `issuer-b`,
    /// with a standard write burst of `burst` per issuer.
    async fn two_issuer_management(burst: u32) -> Router {
        two_issuer_management_with(&[], burst).await
    }

    async fn two_issuer_management_with(overrides: &[(&str, &str)], burst: u32) -> Router {
        two_issuer_management_tiered(overrides, burst, "standard").await
    }

    /// Management routes over `issuer-a` (standard) and `issuer-b` in
    /// `issuer_b_tier`. The standard write burst is `burst` and the sandbox
    /// burst is 1, each with one token per 600 seconds.
    async fn two_issuer_management_tiered(
        overrides: &[(&str, &str)],
        burst: u32,
        issuer_b_tier: &str,
    ) -> Router {
        use crate::server::auth::tests::{rotation_public_jwk, test_public_jwk};

        let config = Config::load_from_overrides(overrides).unwrap();
        let mut state = crate::test_utils::test_app_state(None).await;
        let key = |key: crate::domain::models::credential::PublicJwk| {
            serde_json::json!({
                "kid": key.key_id(),
                "alg": format!("{:?}", key.algorithm()),
                "jwk": key.jwk(),
            })
        };
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [
                { "id": "issuer-a", "aggregation_id": uuid::Uuid::new_v4(), "keys": [key(test_public_jwk())] },
                { "id": "issuer-b", "aggregation_id": uuid::Uuid::new_v4(), "tier": issuer_b_tier, "keys": [key(rotation_public_jwk())] },
            ],
            "admins": []
        }))
        .unwrap();
        state.set_issuer_registry(Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));
        management_with_budgets(&config, state, burst)
    }

    /// Management routes over `state` with the standard write burst set to
    /// `burst` and the sandbox burst to 1, each with one token per 600 seconds.
    fn management_with_budgets(config: &Config, mut state: AppState, burst: u32) -> Router {
        use crate::domain::models::tier::IssuerTier;

        let (auth_gate, _, _) = build_governor_configs(&config.rate_limit).unwrap();
        for (tier, burst) in [(IssuerTier::Standard, burst), (IssuerTier::Sandbox, 1)] {
            let limits = state.tier_limits_mut(tier);
            limits.write_burst_size = std::num::NonZeroU32::new(burst).unwrap();
            limits.write_period = Duration::from_secs(600);
        }
        state.issuer_rate_limiter = Arc::new(crate::server::rate_limit::IssuerRateLimiter::new(
            &state.tiers,
        ));
        management_routes(state.clone(), auth_gate).with_state(state)
    }

    /// One client IP for every request, as behind a shared NAT or proxy.
    async fn patch_statuses(router: &Router, token: &str) -> axum::response::Response {
        patch_statuses_from(router, token, IpAddr::V4(Ipv4Addr::LOCALHOST)).await
    }

    async fn patch_statuses_from(
        router: &Router,
        token: &str,
        client: IpAddr,
    ) -> axum::response::Response {
        patch_statuses_via(router, token, client, None).await
    }

    /// A request whose TCP peer is `peer`, optionally carrying
    /// `X-Forwarded-For`.
    async fn patch_statuses_via(
        router: &Router,
        token: &str,
        peer: IpAddr,
        forwarded_for: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method(Method::PATCH)
            .uri(format!(
                "{API_V1_PREFIX}/status-lists/{}/statuses",
                uuid::Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .extension(axum::extract::ConnectInfo(SocketAddr::new(peer, 12345)));
        if let Some(forwarded_for) = forwarded_for {
            request = request.header("x-forwarded-for", forwarded_for);
        }
        let request = request.body(Body::from(r#"{"statuses":[]}"#)).unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    async fn assert_contract_429(response: axum::response::Response) {
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("429 must carry Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry_after >= 1);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "too_many_requests");
    }

    #[tokio::test]
    async fn test_issuers_behind_one_ip_have_independent_write_budgets() {
        use crate::server::auth::tests::{rotation_private_pem, test_ec_private_pem};

        let management = two_issuer_management(1).await;
        let token_a = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
        let token_b = issuer_token("issuer-b", "rotation-key", &rotation_private_pem());

        let first = patch_statuses(&management, &token_a).await;
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_contract_429(patch_statuses(&management, &token_a).await).await;

        let other = patch_statuses(&management, &token_b).await;
        assert_ne!(
            other.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "issuer-b must not share issuer-a's bucket"
        );
    }

    #[tokio::test]
    async fn test_a_sandbox_issuer_spends_its_tiers_request_budget() {
        use crate::server::auth::tests::{rotation_private_pem, test_ec_private_pem};

        let management = two_issuer_management_tiered(&[], 3, "sandbox").await;
        let standard = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
        let sandbox = issuer_token("issuer-b", "rotation-key", &rotation_private_pem());

        assert_ne!(
            patch_statuses(&management, &sandbox).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(patch_statuses(&management, &sandbox).await).await;
        for _ in 0..3 {
            assert_ne!(
                patch_statuses(&management, &standard).await.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "the standard tier keeps its own, larger budget"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_a_hosted_issuer_spends_the_budget_of_its_stored_tier() {
        use crate::domain::models::credential::AggregationId;
        use crate::domain::models::hosted_issuer::{
            HostedIssuer, HostedIssuerKey, HostedIssuerKeyState, HostedIssuerState,
        };
        use crate::domain::ports::HostedIssuerStore;
        use crate::server::auth::tests::{test_ec_private_pem, test_public_jwk};

        let db = crate::test_utils::sqlite_test_db(None).await;
        let store = Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(db.clone()));
        let issuer_id = uuid::Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        store
            .create_issuer(HostedIssuer {
                id: issuer_id.clone(),
                display_name: None,
                tier: "sandbox".into(),
                state: HostedIssuerState::Active,
                owner: None,
                created_at: now,
                expires_at: Some(now + time::Duration::days(1)),
                version: 1,
                aggregation_id: AggregationId::generate(),
            })
            .await
            .unwrap();
        let jwk = test_public_jwk();
        store
            .add_key(HostedIssuerKey {
                kid: jwk.key_id().to_owned(),
                issuer_id: issuer_id.clone(),
                jwk,
                created_at: now,
                not_before: None,
                not_after: None,
                state: HostedIssuerKeyState::Active,
            })
            .await
            .unwrap();
        let mut state = crate::test_utils::test_app_state(Some(db)).await;
        state.issuer_key_resolver = crate::setup::build_issuer_key_resolver(
            Arc::new(crate::server::auth::issuer_registry::RegistryHandle::empty()),
            Some(store),
        );
        let config = Config::load_from_overrides(&[]).unwrap();
        let management = management_with_budgets(&config, state, 100);
        let token = issuer_token(&issuer_id, "test-key", &test_ec_private_pem());

        assert_ne!(
            patch_statuses(&management, &token).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(patch_statuses(&management, &token).await).await;
    }

    async fn get_credentials(router: &Router, token: &str) -> axum::response::Response {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("{API_V1_PREFIX}/credentials"))
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .extension(axum::extract::ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                12345,
            )))
            .body(Body::empty())
            .unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_credentials_route_spends_the_issuers_budget() {
        use crate::server::auth::tests::{rotation_private_pem, test_ec_private_pem};

        let management = two_issuer_management(2).await;
        let token_a = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
        let token_b = issuer_token("issuer-b", "rotation-key", &rotation_private_pem());

        // Reads and writes share one bucket per issuer.
        assert_ne!(
            patch_statuses(&management, &token_a).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_ne!(
            get_credentials(&management, &token_a).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(get_credentials(&management, &token_a).await).await;
        assert_ne!(
            get_credentials(&management, &token_b).await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "issuer-b must not share issuer-a's bucket"
        );
    }

    #[test]
    fn test_issuer_rate_limit_rejections_are_counted() {
        use crate::server::auth::tests::test_ec_private_pem;

        let metrics = crate::test_utils::metrics_after(async {
            let management = two_issuer_management(1).await;
            let token = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
            for _ in 0..3 {
                patch_statuses(&management, &token).await;
            }
        });
        let line = metrics
            .lines()
            .find(|line| {
                line.starts_with("issuer_rate_limited_total{")
                    && line.contains("issuer=\"issuer-a\"")
                    && line.contains("tier=\"standard\"")
            })
            .unwrap_or_else(|| panic!("missing issuer_rate_limited_total: {metrics}"));
        assert!(line.ends_with(" 2"), "{line}");
    }

    #[tokio::test]
    async fn test_forged_iss_cannot_spend_another_issuers_write_budget() {
        use crate::server::auth::tests::{rotation_private_pem, test_ec_private_pem};

        let management = two_issuer_management(1).await;
        // Claims issuer-a but is signed with issuer-b's key, and the reverse
        // pairing of kid and key: neither verifies.
        let forged = [
            issuer_token("issuer-a", "rotation-key", &rotation_private_pem()),
            issuer_token("issuer-a", "test-key", &rotation_private_pem()),
        ];
        for token in &forged {
            let response = patch_statuses(&management, token).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let genuine = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
        let response = patch_statuses(&management, &genuine).await;
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "forged requests must not have drained issuer-a's bucket"
        );
    }

    #[tokio::test]
    async fn test_verified_writes_from_one_ip_do_not_spend_the_default_auth_gate() {
        use crate::server::auth::tests::{rotation_private_pem, test_ec_private_pem};

        let config = Config::load_from_overrides(&[]).unwrap();
        let writes = config.rate_limit.strict_burst_size + 1;
        let management = two_issuer_management(writes).await;
        let tokens = [
            issuer_token("issuer-a", "test-key", &test_ec_private_pem()),
            issuer_token("issuer-b", "rotation-key", &rotation_private_pem()),
        ];
        for token in &tokens {
            for _ in 0..writes {
                let response = patch_statuses(&management, token).await;
                assert_ne!(
                    response.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "verified writes must only spend the issuer's own budget"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_spoofed_forwarding_headers_do_not_evade_the_auth_gate() {
        let management = two_issuer_management_with(
            &[
                ("rate_limit.strict_burst_size", "1"),
                ("rate_limit.strict_period_secs", "600"),
            ],
            100,
        )
        .await;
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        // Without trusted proxies, a fresh X-Forwarded-For per request does
        // not create a fresh bucket.
        assert_eq!(
            patch_statuses_via(&management, "not-a-token", attacker, Some("203.0.113.1"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_contract_429(
            patch_statuses_via(&management, "not-a-token", attacker, Some("203.0.113.2")).await,
        )
        .await;
    }

    #[tokio::test]
    async fn test_clients_behind_a_trusted_proxy_have_their_own_auth_gate() {
        let management = two_issuer_management_with(
            &[
                ("rate_limit.strict_burst_size", "1"),
                ("rate_limit.strict_period_secs", "600"),
                ("rate_limit.trusted_proxies", "10.0.0.0/8"),
            ],
            100,
        )
        .await;
        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(
            patch_statuses_via(&management, "not-a-token", proxy, Some("203.0.113.1"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        // The same client stays charged even when it prepends a forged hop.
        assert_contract_429(
            patch_statuses_via(
                &management,
                "not-a-token",
                proxy,
                Some("192.0.2.99, 203.0.113.1"),
            )
            .await,
        )
        .await;
        // Another client behind the same proxy has its own budget.
        assert_eq!(
            patch_statuses_via(&management, "not-a-token", proxy, Some("203.0.113.2"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_spent_auth_failures_never_block_a_verified_issuer_on_the_same_address() {
        use crate::server::auth::tests::test_ec_private_pem;

        let management = two_issuer_management_with(
            &[
                ("rate_limit.strict_burst_size", "1"),
                ("rate_limit.strict_period_secs", "600"),
            ],
            100,
        )
        .await;
        let genuine = issuer_token("issuer-a", "test-key", &test_ec_private_pem());

        assert_eq!(
            patch_statuses(&management, "not-a-token").await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_contract_429(patch_statuses(&management, "not-a-token").await).await;
        // Clients behind one NAT or proxy share the address: a verified issuer
        // among them is never refused for the others' bad tokens.
        assert_ne!(
            patch_statuses(&management, &genuine).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(patch_statuses(&management, "not-a-token").await).await;
    }

    /// Answers every `kid` as unknown and counts how often it was asked, as a
    /// hosted store does with one query per lookup.
    #[derive(Debug, Default)]
    struct CountingResolver(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl crate::domain::ports::IssuerKeyResolver for CountingResolver {
        async fn resolve(
            &self,
            _kid: &str,
        ) -> Result<
            Arc<crate::domain::models::credential::ResolvedKey>,
            crate::domain::models::credential::KeyResolveError,
        > {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::domain::models::credential::KeyResolveError::UnknownKid)
        }
    }

    #[tokio::test]
    async fn test_admission_bounds_key_lookups_before_auth() {
        use crate::server::auth::tests::test_ec_private_pem;

        let config = Config::load_from_overrides(&[
            ("tiers.standard.write_burst_size", "2"),
            ("rate_limit.admission_burst_size", "2"),
            ("rate_limit.admission_per_second", "1"),
        ])
        .unwrap();
        let resolver = Arc::new(CountingResolver::default());
        let mut state = crate::test_utils::test_app_state(None).await;
        state.issuer_key_resolver = resolver.clone();
        let management = management_with_budgets(&config, state, 2);
        let token = issuer_token("issuer-x", "unknown-kid", &test_ec_private_pem());

        let mut refused = 0;
        for _ in 0..10 {
            let response = patch_statuses(&management, &token).await;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                refused += 1;
                assert_contract_429(response).await;
            }
        }
        let lookups = resolver.0.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            lookups + refused,
            10,
            "a refused request never reached auth"
        );
        // The burst, plus at most one token replenished on a slow runner.
        assert!(lookups <= 3, "{lookups} key lookups passed admission");
    }

    #[tokio::test]
    async fn test_admission_never_refuses_a_lone_issuer_within_its_budget() {
        use crate::server::auth::tests::test_ec_private_pem;

        // The smallest admission budget startup accepts for this tier.
        let management = two_issuer_management_with(
            &[
                ("tiers.standard.write_burst_size", "5"),
                ("rate_limit.admission_burst_size", "5"),
                ("rate_limit.admission_per_second", "1"),
            ],
            5,
        )
        .await;
        let token = issuer_token("issuer-a", "test-key", &test_ec_private_pem());
        for _ in 0..5 {
            assert_ne!(
                patch_statuses(&management, &token).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
    }

    #[tokio::test]
    async fn test_ip_governor_rejects_with_the_error_contract() {
        let config = Config::load_from_overrides(&[
            ("rate_limit.strict_burst_size", "1"),
            ("rate_limit.strict_period_secs", "600"),
        ])
        .unwrap();
        let (auth_gate, _, _) = build_governor_configs(&config.rate_limit).unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        let management = management_routes(state.clone(), auth_gate).with_state(state);

        let first = patch_statuses(&management, "not-a-token").await;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        assert_contract_429(patch_statuses(&management, "not-a-token").await).await;
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

    fn one_request_budget(overrides: &[(&str, &str)]) -> Config {
        let mut overrides = overrides.to_vec();
        overrides.extend([
            ("rate_limit.permissive_burst_size", "1"),
            ("rate_limit.permissive_period_secs", "600"),
        ]);
        Config::load_from_overrides(&overrides).unwrap()
    }

    async fn public_with_one_request(overrides: &[(&str, &str)]) -> Router {
        let config = one_request_budget(overrides);
        let (_, permissive, _) = build_governor_configs(&config.rate_limit).unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        public_routes(permissive).with_state(state)
    }

    async fn admin_with_one_request(overrides: &[(&str, &str)]) -> Router {
        use crate::server::auth::tests::test_public_jwk;

        let config = one_request_budget(overrides);
        let (_, _, admin_governor) = build_governor_configs(&config.rate_limit).unwrap();
        let mut state = crate::test_utils::test_app_state(None).await;
        let key = test_public_jwk();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [],
            "admins": [{
                "id": "admin-1",
                "scopes": ["issuers:read"],
                "keys": [{
                    "kid": key.key_id(),
                    "alg": format!("{:?}", key.algorithm()),
                    "jwk": key.jwk(),
                }],
            }],
        }))
        .unwrap();
        state.admin_registry = Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        );
        state.admin_auth.audiences = vec!["status-list-server-admin".into()];
        admin_routes(
            state.clone(),
            &config,
            prometheus::Registry::new(),
            admin_governor,
        )
        .with_state(state)
    }

    fn admin_token() -> String {
        use crate::server::auth::tests::test_ec_private_pem;

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("statuslist-admin+jwt".to_string());
        header.kid = Some("test-key".to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": "admin-1",
                "iat": now,
                "exp": now + 300,
                "aud": "status-list-server-admin",
            }),
            &jsonwebtoken::EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    async fn get_via(
        router: &Router,
        uri: &str,
        bearer: Option<&str>,
        peer: IpAddr,
        forwarded_for: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .uri(uri)
            .extension(axum::extract::ConnectInfo(SocketAddr::new(peer, 12345)));
        if let Some(token) = bearer {
            request = request.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(forwarded_for) = forwarded_for {
            request = request.header("x-forwarded-for", forwarded_for);
        }
        router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn public_read(
        router: &Router,
        peer: IpAddr,
        forwarded_for: Option<&str>,
    ) -> axum::response::Response {
        let uri = format!("{API_V1_PREFIX}/aggregation");
        get_via(router, &uri, None, peer, forwarded_for).await
    }

    async fn admin_read(
        router: &Router,
        peer: IpAddr,
        forwarded_for: Option<&str>,
    ) -> axum::response::Response {
        let token = admin_token();
        get_via(
            router,
            "/admin/v1/issuers",
            Some(&token),
            peer,
            forwarded_for,
        )
        .await
    }

    #[tokio::test]
    async fn test_spoofed_forwarding_headers_do_not_evade_the_public_limiter() {
        let public = public_with_one_request(&[]).await;
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        assert_ne!(
            public_read(&public, attacker, None).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(public_read(&public, attacker, Some("203.0.113.1")).await).await;
    }

    #[tokio::test]
    async fn test_clients_behind_a_trusted_proxy_have_their_own_public_bucket() {
        let public = public_with_one_request(&[("rate_limit.trusted_proxies", "10.0.0.0/8")]).await;
        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert_ne!(
            public_read(&public, proxy, Some("203.0.113.1"))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(public_read(&public, proxy, Some("192.0.2.99, 203.0.113.1")).await)
            .await;
        assert_ne!(
            public_read(&public, proxy, Some("203.0.113.2"))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn test_ipv6_clients_in_one_slash_64_share_a_public_bucket() {
        let public = public_with_one_request(&[]).await;
        let ip = |value: &str| value.parse::<IpAddr>().unwrap();

        assert_ne!(
            public_read(&public, ip("2001:db8:1:2::1"), None)
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_contract_429(public_read(&public, ip("2001:db8:1:2::ffff"), None).await).await;
        assert_ne!(
            public_read(&public, ip("2001:db8:1:3::1"), None)
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn test_spoofed_forwarding_headers_do_not_evade_the_admin_limiter() {
        let admin = admin_with_one_request(&[]).await;
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));

        assert_eq!(
            admin_read(&admin, attacker, None).await.status(),
            StatusCode::OK
        );
        assert_contract_429(admin_read(&admin, attacker, Some("203.0.113.1")).await).await;
    }

    #[tokio::test]
    async fn test_clients_behind_a_trusted_proxy_have_their_own_admin_bucket() {
        let admin = admin_with_one_request(&[("rate_limit.trusted_proxies", "10.0.0.0/8")]).await;
        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(
            admin_read(&admin, proxy, Some("203.0.113.1"))
                .await
                .status(),
            StatusCode::OK
        );
        assert_contract_429(admin_read(&admin, proxy, Some("192.0.2.99, 203.0.113.1")).await).await;
        assert_eq!(
            admin_read(&admin, proxy, Some("203.0.113.2"))
                .await
                .status(),
            StatusCode::OK
        );
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

    #[allow(
        clippy::await_holding_lock,
        reason = "metrics_test_lock must stay held while tests swap the global meter provider"
    )]
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
            body.contains("http_server_requests_total")
                && body.contains("route=\"/ok\"")
                && body.contains("status_class=\"2xx\""),
            "expected 2xx counter for /ok; body:\n{body}"
        );
        assert!(
            body.contains("http_server_requests_total")
                && body.contains("route=\"/boom\"")
                && body.contains("status_class=\"5xx\""),
            "expected 5xx counter for /boom; body:\n{body}"
        );
        assert!(
            body.contains("http_server_duration_seconds_count"),
            "expected duration histogram count; body:\n{body}"
        );
    }

    #[allow(
        clippy::await_holding_lock,
        reason = "metrics_test_lock must stay held while tests swap the global meter provider"
    )]
    #[tokio::test]
    async fn http_metrics_listener_label_is_not_unknown() {
        use crate::utils::metrics::{metrics_test_lock, setup_metrics};
        use opentelemetry_sdk::Resource;
        use prometheus::{Encoder, Registry, TextEncoder};

        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let telemetry = crate::config::TelemetryConfig {
            environment: crate::config::TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &telemetry,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        let config = Config::load_from_overrides(&[]).unwrap();
        let state = crate::test_utils::test_app_state(None).await;

        async fn ok_handler() -> impl IntoResponse {
            "ok"
        }

        let router = with_listener_name(
            with_common_layers(
                Router::<AppState>::new().route("/ok", get(ok_handler)),
                &config,
            ),
            "management",
        )
        .with_state(state);

        let resp = router
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

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");

        assert!(
            body.contains("listener=\"management\"") && !body.contains("listener=\"unknown\""),
            "expected a real listener label, not unknown; body:\n{body}"
        );
    }

    #[allow(
        clippy::await_holding_lock,
        reason = "metrics_test_lock must stay held while tests swap the global meter provider"
    )]
    #[tokio::test]
    async fn panicking_handler_records_5xx_metric() {
        use crate::utils::metrics::{metrics_test_lock, setup_metrics};
        use opentelemetry_sdk::Resource;
        use prometheus::{Encoder, Registry, TextEncoder};
        use tower_http::catch_panic::CatchPanicLayer;

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

        async fn boom_handler() -> StatusCode {
            panic!("boom");
        }

        let router = Router::new()
            .route("/boom", get(boom_handler))
            .layer(CatchPanicLayer::new())
            .layer(middleware::from_fn(track_http_metrics))
            .with_state(());

        let resp = router
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
            body.contains("http_server_requests_total")
                && body.contains("route=\"/boom\"")
                && body.contains("status_class=\"5xx\""),
            "expected 5xx counter for a panicking handler; body:\n{body}"
        );
    }
}
