use axum::{
    http::Method,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use dotenvy::dotenv;
use serde::Serialize;
use status_list_server::web::auth::auth;
use status_list_server::web::handlers::{credential_handler, get_status_list};
use status_list_server::{
    utils::state::setup,
    web::handlers::status_list::{
        publish_token_status::publish_token_status, update_token_status::update_token_status,
    },
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

async fn welcome() -> impl IntoResponse {
    "Status list Server"
}

#[derive(Serialize)]
struct HealthCheckResponse {
    status: String,
}

async fn health_check() -> impl IntoResponse {
    Json(HealthCheckResponse {
        status: "OK".to_string(),
    })
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    config_tracing();

    let state = setup().await;

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    let protected_routes = Router::new()
        .route("/publish", post(publish_token_status))
        .route("/update", patch(update_token_status))
        .route_layer(from_fn_with_state(state.clone(), auth));

    let router = Router::new()
        .route("/", get(welcome))
        .route("/health", get(health_check))
        .route("/credentials", post(credential_handler))
        .nest(
            "/statuslists",
            Router::new()
            .merge(protected_routes)
            .route("/{list_id}", get(get_status_list)),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CatchPanicLayer::new())
                .layer(cors),
        )
        .with_state(state);

    let addr = "0.0.0.0:8000";
    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("listening on {addr}");
    axum::serve(listener, router).await.unwrap()
}

fn config_tracing() {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }

    use tracing::Level;
    use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

    let tracing_layer = tracing_subscriber::fmt::layer();
    let filter = filter::Targets::new()
        .with_target("hyper::proto", Level::INFO)
        .with_target("tower_http::trace", Level::DEBUG)
        .with_default(Level::DEBUG);

    tracing_subscriber::registry()
        .with(tracing_layer)
        .with(filter)
        .init();
}
