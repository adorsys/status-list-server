use color_eyre::{Result, eyre::eyre};
use dotenvy::dotenv;
use rustls::crypto::aws_lc_rs;
use status_list_server::cert_manager::setup_cert_renewal_scheduler;
use status_list_server::state::build_state;
use status_list_server::{config::Config as AppConfig, startup::HttpServer};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tracing::warn;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
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
    setup_cert_renewal_scheduler(
        cert_manager.clone(),
        &config.server.cert.renewal_cron_schedule,
    )
    .await?;

    let http_server = HttpServer::new(&config, app_state).await?;

    // Zero-init cert-chain cache counters now that the metrics recorder is
    // installed (HttpServer::new → attach_metrics → setup_metrics).
    cert_manager.init_cert_chain_cache_counters();

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
