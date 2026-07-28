use color_eyre::{Result, eyre::eyre};
use dotenvy::dotenv;
use rustls::crypto::aws_lc_rs;
use status_list_server::cert_manager::{describe_renewal_metrics, setup_cert_renewal_scheduler};
use status_list_server::setup::{build_state_with_cert_manager, setup_history_cleanup_scheduler};
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
    color_eyre::install()?;

    aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| eyre!("Failed to set crypto provider: {e:?}"))?;

    describe_renewal_metrics();

    let config = AppConfig::load()?;
    let (app_state, cert_manager) = build_state_with_cert_manager(&config).await?;

    setup_cert_renewal_scheduler(
        cert_manager.clone(),
        &config.server.cert.renewal_cron_schedule,
    )
    .await?;

    setup_history_cleanup_scheduler(app_state.clone(), "0 0 0 * * *").await?;

    let http_server = HttpServer::new(&config, app_state).await?;

    cert_manager.init_cert_chain_cache_counters();
    cert_manager.init_renewal_counters();

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
