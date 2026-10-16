use std::net::SocketAddr;
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
use governor::middleware::NoOpMiddleware;
use hyper::Method;
use prometheus::Registry;
use tokio::net::TcpListener;
use tokio::sync::watch;
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

use crate::config::{API_V1_PREFIX, Config};

use crate::server::handlers::{
    allocate_indices_route, credential_handler, get_aggregation, get_credential,
    get_issuer_aggregation, get_status_list, publish_status_route, update_status_route,
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
        let (strict_governor, issuer_governor, permissive_governor) =
            build_governor_configs(&config.rate_limit)?;

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
            with_common_layers(
                management_routes(state.clone(), issuer_governor, strict_governor),
                config,
            ),
            "management",
        )
        .with_state(state.clone());

        let admin_router = with_listener_name(
            with_common_layers(admin_routes(config, prometheus_registry), config),
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

/// Internet-facing: never register management or admin routes here.
fn public_routes(
    permissive_governor: Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
) -> Router<AppState> {
    let public_reads = Router::new()
        .route("/aggregation", get(get_aggregation))
        .route("/aggregation/{aggregation_id}", get(get_issuer_aggregation))
        .route("/status-lists/{list_id}", get(get_status_list))
        .layer(GovernorLayer::new(permissive_governor));

    Router::new()
        .route("/", get(service_document))
        .route("/health", get(health::live))
        .route("/health/live", get(health::live))
        .nest(API_V1_PREFIX, public_reads)
}

fn management_routes(
    state: AppState,
    issuer_governor: Arc<GovernorConfig<SmartIpKeyExtractor, NoOpMiddleware>>,
    strict_governor: Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>,
) -> Router<AppState> {
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
        .route_layer(from_fn_with_state(state.clone(), auth))
        .layer(GovernorLayer::new(issuer_governor));

    let credentials = Router::new()
        .route("/credentials", post(credential_handler))
        .layer(GovernorLayer::new(strict_governor));

    Router::new().nest(
        API_V1_PREFIX,
        Router::new().merge(protected).merge(credentials),
    )
}

fn admin_routes(config: &Config, registry: Registry) -> Router<AppState> {
    let router = Router::new().route("/health/ready", get(health::ready));
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
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_management_register_issuers_and_public_serve_aggregation() {
        let config = Config::load_from_overrides(&[]).unwrap();
        let (strict, issuer, permissive) = build_governor_configs(&config.rate_limit).unwrap();
        let state = crate::test_utils::test_app_state(None).await;
        let management = management_routes(state.clone(), issuer, strict).with_state(state.clone());
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
        assert_eq!(registration.status(), StatusCode::ACCEPTED);
        let registration: serde_json::Value = serde_json::from_slice(
            &to_bytes(registration.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let aggregation_id = registration["aggregation_id"].as_str().unwrap();

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

        let config =
            Config::load_from_overrides(&[("APP_SERVER__ENABLE_METRICS", "true")]).unwrap();
        let (strict, issuer, permissive) = build_governor_configs(&config.rate_limit).unwrap();

        let state = crate::test_utils::test_app_state(None).await;
        let aggregation_id = register_issuer(&state.service, "issuer1").await;
        let list_id = uuid::Uuid::new_v4().to_string();
        publish_list(&state.service, "issuer1", &list_id).await;

        let public = public_routes(permissive).with_state(state.clone());
        let management = management_routes(state.clone(), issuer, strict).with_state(state.clone());
        let admin = admin_routes(&config, prometheus::Registry::new()).with_state(state);

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
                Method::POST,
                &format!("{API_V1_PREFIX}/credentials"),
                MANAGEMENT,
            ),
            (
                Method::GET,
                &format!("{API_V1_PREFIX}/credentials"),
                MANAGEMENT,
            ),
            (Method::GET, "/health/ready", ADMIN),
            (Method::GET, "/metrics", ADMIN),
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
        let (_, _, permissive) = build_governor_configs(&config.rate_limit).unwrap();
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
        let (_, _, permissive) = build_governor_configs(&config.rate_limit).unwrap();
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

        let body = format!(
            r#"{{"issuer":"issuer1","public_key":{}}}"#,
            crate::test_fixtures::TEST_EC_PUBLIC_JWK
        );
        let (first_half, second_half) = body.as_bytes().split_at(body.len() / 2);
        let mut slow = TcpStream::connect(management_addr).await.unwrap();
        let head = format!(
            "POST {API_V1_PREFIX}/credentials HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        slow.write_all(head.as_bytes()).await.unwrap();
        slow.write_all(first_half).await.unwrap();
        slow.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        shutdown_tx.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut run_handle)
                .await
                .is_err(),
            "run returned while a request was still in flight on the management listener"
        );

        slow.write_all(second_half).await.unwrap();
        slow.flush().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut response))
            .await
            .expect("in-flight request was not answered during graceful shutdown")
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 202"),
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

    #[allow(clippy::await_holding_lock)]
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

    #[allow(clippy::await_holding_lock)]
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

    #[allow(clippy::await_holding_lock)]
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
