use axum::{
    Router,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post, put},
};
use color_eyre::eyre::Context;
use hyper::Method;
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::Config,
    utils::metrics::{metrics_handler, setup_metrics, start_metrics_collector},
    utils::state::AppState,
    web::{
        auth::auth,
        handlers::{
            credential_handler, get_status_list, openapi_json, publish_status, update_status,
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
            .route("/openapi.json", get(openapi_json))
            .nest("/statuslists", protocol_routes())
            .nest("/api/v1", api_v1_routes(state.clone()))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors)
            .with_state(state);

        router = attach_metrics(router, config);

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
