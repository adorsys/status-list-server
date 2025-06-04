use core::panic;

use axum::{
    http::Method,
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use dotenvy::dotenv;
use serde::Serialize;
use status_list_server::config::Config as AppConfig;
use status_list_server::utils::state::setup;
use status_list_server::web::handlers::status_list::publish_token_status::publish_token_status;
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

#[tokio::main]
async fn main() -> Result<(), color_eyre::Result<()>> {
    config_tracing();
    dotenv().ok();
    color_eyre::install()?;

    let state = setup().await;
    let config = AppConfig::load()?;

    let server = HttpServer::new(config, state).await?;
    server.run().await?;
    Ok(())
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
