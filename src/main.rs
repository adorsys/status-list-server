use color_eyre::{Result, eyre::eyre};
use dotenvy::dotenv;
use rustls::crypto::aws_lc_rs;
#[cfg(feature = "acme")]
use status_list_server::cert_manager::setup_cert_renewal_scheduler;
#[cfg(not(feature = "acme"))]
use status_list_server::setup::build_state;
#[cfg(feature = "acme")]
use status_list_server::setup::build_state_with_cert_manager;
use status_list_server::setup::{run_list_quota_command, setup_snapshot_cleanup_scheduler};
use status_list_server::telemetry::init_telemetry;
use status_list_server::{config::Config as AppConfig, startup::HttpServer};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tokio::sync::watch;
#[cfg(feature = "acme")]
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("issuer-export") {
        return export_issuers(&args[1..]).await;
    }
    let config = AppConfig::load()?;
    if args.first().map(String::as_str) == Some("list-quota") {
        let action = args.get(1).map(String::as_str).unwrap_or_default();
        println!("{}", run_list_quota_command(&config, action).await?);
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("issuer-registry") {
        let path = config
            .management_auth
            .issuers_file
            .as_deref()
            .ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "management_auth.issuers_file is required for issuer-registry validation"
                )
            })?;
        let registry =
            status_list_server::server::auth::issuer_registry::IssuerRegistry::from_file(path)?;
        println!(
            "issuer registry is valid: {} trusted keys",
            registry.key_count()
        );
        return Ok(());
    }

    // Initialize telemetry (tracing + metrics) based on environment.
    // The guard must be held until shutdown to flush pending OTLP spans.
    let (_telemetry_guard, prometheus_registry) = init_telemetry(&config.telemetry)?;

    // Install the crypto provider
    aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| eyre!("Failed to set crypto provider: {e:?}"))?;

    // Load configuration and build the app state
    let config = AppConfig::load()?;

    #[cfg(feature = "acme")]
    let (app_state, cert_manager) = build_state_with_cert_manager(&config).await?;

    #[cfg(not(feature = "acme"))]
    let app_state = build_state(&config).await?;

    // Setup certificate renewal scheduler
    #[cfg(feature = "acme")]
    setup_cert_renewal_scheduler(
        cert_manager.clone(),
        &config.server.cert.renewal_cron_schedule,
    )
    .await?;

    // Setup historical snapshot cleanup scheduler (runs daily at midnight UTC)
    // This deletes snapshots older than snapshot_retention_secs to prevent
    // unbounded database growth and mitigate privacy risks (draft-21 §12.7)
    setup_snapshot_cleanup_scheduler(app_state.clone(), "0 0 0 * * *").await?;

    let http_server = HttpServer::new(&config, app_state, prometheus_registry).await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    HttpServer::install_shutdown_handler(&shutdown_tx);

    #[cfg(feature = "acme")]
    {
        // Zero-init cert-chain cache counters now that the metrics recorder is installed.
        cert_manager.init_cert_chain_cache_counters();

        // Zero-init renewal counters so they appear in Prometheus scrapes
        cert_manager.init_renewal_counters();

        // Initial certificate request
        tokio::spawn(async move {
            if let Err(e) = cert_manager.renew_cert_if_needed().await {
                warn!("Certificate initialization failed: {e}");
            }
        });
    }

    http_server.run(shutdown_rx).await?;
    Ok(())
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "sqlite"))]
async fn export_issuers(args: &[String]) -> Result<()> {
    use sea_orm::Database;
    let value = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str())
    };
    let url = value("--database-url").ok_or_else(|| eyre!("--database-url is required"))?;
    let output = value("--output").unwrap_or("issuers.yaml");
    let db = Database::connect(url).await?;
    let credentials =
        status_list_server::outbound::sql::issuer_export::legacy_issuer_credentials(&db)
            .await
            .map_err(|err| eyre!(err.to_string()))?;
    let issuer_count = credentials.len();
    let yaml =
        status_list_server::server::auth::issuer_registry::IssuerRegistry::export_legacy_issuers(
            credentials
                .into_iter()
                .map(|row| (row.issuer, row.aggregation_id, row.public_key)),
        )?;
    std::fs::write(output, yaml)?;
    println!("exported {} issuer(s) to {}", issuer_count, output);
    Ok(())
}

#[cfg(not(any(feature = "postgres", feature = "mysql", feature = "sqlite")))]
async fn export_issuers(_: &[String]) -> Result<()> {
    Err(eyre!("issuer export requires a SQL database feature"))
}
