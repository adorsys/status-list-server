use axum::{
    http::Method,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use status_list_server::utils::state::setup;
use status_list_server::web::handlers::status_list::publish_token_status::publish_token_status;
use status_list_server::web::handlers::{credential_handler, get_status_list, status_list_aggregation::aggregate_status_lists};
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

#[tokio::main]
async fn main() {
    dotenv().ok();
    config_tracing();

    let state = setup().await;

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/", get(welcome))
        .route("/credentials", post(credential_handler))
        .route("/statuslists/{list_id}", get(get_status_list))
        .route("/statuslists/publish", post(publish_token_status))
        .route("/statuslists/aggregate", post(aggregate_status_lists))
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
