use opentelemetry::{KeyValue, global};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) const TARGET_DATABASE: &str = "database";
pub(crate) const TARGET_TOKEN_SIGNING_KEY: &str = "token_signing_key";

pub(crate) fn record_rotation(target: &'static str, success: bool) {
    let meter = global::meter("status-list-server");
    let outcome = if success { "success" } else { "failure" };
    let attrs = [
        KeyValue::new("target", target),
        KeyValue::new("outcome", outcome),
    ];

    meter
        .u64_counter("credential_rotation_total")
        .with_description("Credential rotation attempts by target and outcome.")
        .build()
        .add(1, &attrs);

    if success {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or_default();
        meter
            .f64_gauge("credential_rotation_last_success_timestamp")
            .with_description("Unix timestamp of the last successful credential rotation.")
            .with_unit("s")
            .build()
            .record(timestamp, &[KeyValue::new("target", target)]);
    }
}
