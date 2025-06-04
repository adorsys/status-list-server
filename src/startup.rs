use axum::{
    response::IntoResponse,
    routing::{get, patch, post},
    Router,
};
use color_eyre::eyre::eyre;
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
    web::handlers::{
        credential_handler, get_status_list, publish_token_status, update_token_status,
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
            .nest("/statuslists", status_list_routes())
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await
            .map_err(|e| eyre!("failed to bind to port {}\n{e:?}", config.server.port))?;

        Ok(Self { router, listener })
    }

    pub async fn run(self) -> color_eyre::Result<()> {
        tracing::info!("listening on {}", self.listener.local_addr()?);
        axum::serve(self.listener, self.router)
            .await
            .map_err(|e| eyre!("failed to start server: {e:?}"))?;
        Ok(())
    }
}

fn status_list_routes() -> Router<AppState> {
    Router::new()
        .route("/{list_id}", get(get_status_list))
        .route("/publish", post(publish_token_status))
        .route("/update", patch(update_token_status))
}
