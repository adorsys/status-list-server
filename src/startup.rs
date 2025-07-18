use axum::{
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post},
    Router,
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
    utils::state::AppState,
    web::{
        auth::auth,
        handlers::{credential_handler, get_status_list, publish_status, update_status, status_list::aggregation::aggregation},
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
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_origin(Any)
            .allow_headers(Any);

        let router = Router::new()
            .route("/", get(welcome))
            .route("/health", get(health_check))
            .route("/credentials", post(credential_handler))
            .nest("/statuslists", status_list_routes(state.clone()))
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors)
            .with_state(state);

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

fn status_list_routes(state: AppState) -> Router<AppState> {
    let protected_routes = Router::new()
        .route("/publish", post(publish_status))
        .route("/update", patch(update_status))
        .route_layer(from_fn_with_state(state.clone(), auth));

    Router::new()
        .merge(protected_routes)
        .route("/aggregation", get(aggregation))
        .route("/{list_id}", get(get_status_list))
}
