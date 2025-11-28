use color_eyre::eyre::Result;
use metrics_exporter_prometheus::PrometheusHandle;
use metrics_process::Collector;
use std::time::Duration;

/// Initialize Prometheus metrics recorder
pub fn setup_metrics() -> Result<PrometheusHandle> {
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder.install_recorder()?;

    Ok(handle)
}

/// Start the background metrics collector task
pub fn start_metrics_collector() {
    let collector = Collector::default();
    collector.describe();

    tokio::spawn(async move {
        loop {
            collector.collect();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

pub async fn metrics_handler(handle: PrometheusHandle) -> String {
    handle.render()
}
