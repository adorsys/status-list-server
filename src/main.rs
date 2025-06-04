use color_eyre::eyre::eyre;
use dotenvy::dotenv;
use rustls::crypto::aws_lc_rs;
use status_list_server::cert_manager::setup_cert_renewal_scheduler;
use status_list_server::state::build_state;
use status_list_server::{config::Config as AppConfig, startup::HttpServer};
use tracing::warn;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    config_tracing();
    dotenv().ok();
    // Install the default panic and error report hooks
    color_eyre::install()?;

    // Install the crypto provider
    aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| eyre!("Failed to set crypto provider: {e:?}"))?;

    // Load configuration and build the app state
    let config = AppConfig::load()?;
    let app_state = build_state(&config).await?;

    // Setup certificate renewal scheduler
    let cert_manager = app_state.cert_manager.clone();
    setup_cert_renewal_scheduler(cert_manager.clone()).await?;

    let http_server = HttpServer::new(&config, app_state).await?;

    // Initial certificate request
    tokio::spawn(async move {
        if let Err(e) = cert_manager.renew_cert_if_needed().await {
            warn!("Certificate initialization failed: {e}");
        }
    });

    http_server.run().await?;
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
