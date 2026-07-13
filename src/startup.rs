use axum::{
    Router,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post, put},
};
use color_eyre::eyre::{Context, eyre};
use hyper::Method;
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

/// Path of the aggregation route, as registered under `/api/v1`.
const AGGREGATION_ROUTE_PATH: &str = "/api/v1/aggregation";

use crate::{
    config::Config,
    utils::metrics::{metrics_handler, setup_metrics, start_metrics_collector},
    utils::state::AppState,
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

        let mut router = Router::new()
            .route("/", get(welcome))
            .route("/health", get(health_check))
            .nest("/statuslists", protocol_routes())
            .nest("/api/v1", api_v1_routes(state.clone()))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors)
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
        axum::serve(self.listener, self.router)
            .await
            .wrap_err("Failed to start HTTP server")?;
        Ok(())
    }
}

/// Protocol routes for public status list access.
fn protocol_routes() -> Router<AppState> {
    Router::new().route("/{list_id}", get(get_status_list))
}

/// Management API v1 routes.
fn api_v1_routes(state: AppState) -> Router<AppState> {
    let protected = Router::new()
        .nest(
            "/status-lists/{list_id}/statuses",
            Router::new()
                .route("/", put(publish_status))
                .route("/", patch(update_status)),
        )
        .route_layer(from_fn_with_state(state.clone(), auth));

    Router::new()
        .merge(protected)
        .route("/aggregation", get(get_aggregation))
        .route("/credentials", post(credential_handler))
        .route("/status-lists/{list_id}", get(get_status_list))
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
}
