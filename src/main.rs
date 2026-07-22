use color_eyre::{Result, eyre::eyre};
use dotenvy::dotenv;
use rustls::crypto::aws_lc_rs;
use status_list_server::cert_manager::setup_cert_renewal_scheduler;
use status_list_server::state::{build_state, setup_history_cleanup_scheduler};
use status_list_server::telemetry::init_telemetry;
use status_list_server::{config::Config as AppConfig, startup::HttpServer};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tracing::warn;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // Install the default panic and error report hooks
    color_eyre::install()?;

    // Load configuration first so telemetry can read its settings
    let config = AppConfig::load()?;

    // Initialize telemetry (tracing + metrics) based on environment.
    // The guard must be held until shutdown to flush pending OTLP spans.
    let (_telemetry_guard, prometheus_registry) = init_telemetry(&config.telemetry)?;

    // Install the crypto provider
    aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| eyre!("Failed to set crypto provider: {e:?}"))?;

    // Build the app state
    let app_state = build_state(&config).await?;

    // Setup certificate renewal scheduler
    let cert_manager = app_state.cert_manager.clone();
    setup_cert_renewal_scheduler(
        cert_manager.clone(),
        &config.server.cert.renewal_cron_schedule,
    )
    .await?;

    // Setup historical snapshot cleanup scheduler (runs daily at midnight UTC)
    // This deletes snapshots older than history_retention_secs to prevent
    // unbounded database growth and mitigate privacy risks (draft-21 §12.7)
    setup_history_cleanup_scheduler(app_state.clone(), "0 0 0 * * *").await?;

    let http_server = HttpServer::new(&config, app_state, prometheus_registry).await?;

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
