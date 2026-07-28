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

const AGGREGATION_ROUTE_PATH: &str = "/api/v1/aggregation";

use crate::config::Config;
use crate::server::{
    AppState,
    auth::auth,
    handlers::{
        credential_handler, get_aggregation, get_status_list, publish_status, update_status,
    },
};
use crate::utils::metrics::{metrics_handler, setup_metrics, start_metrics_collector};

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
