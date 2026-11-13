use std::sync::Arc;

use moka::future::Cache;
use opentelemetry::{
    metrics::Counter,
    {KeyValue, global},
};

pub(crate) type CertificateChain = Arc<[String]>;

// One CertManager serves a single TLD+1, so only one chain is ever cached.
const CACHE_CAPACITY: u64 = 1;
const HIT_METRIC: &str = "certificate_chain_cache_hits";
const MISS_METRIC: &str = "certificate_chain_cache_misses";
const REPLACEMENT_METRIC: &str = "certificate_chain_cache_replacements";

/// No time-based expiry; renewal replaces the entry.
#[derive(Clone)]
pub(crate) struct CertChainCache {
    inner: Cache<String, CertificateChain>,
    /// Empty means no label.
    domain_label: String,
    hit_counter: Counter<u64>,
    miss_counter: Counter<u64>,
    replacement_counter: Counter<u64>,
}

impl CertChainCache {
    /// Build after telemetry init: counters taken earlier stay no-ops forever.
    pub(crate) fn new(domain: impl AsRef<str>) -> Self {
        let meter = global::meter("status-list-server");

        let hit_counter = meter
            .u64_counter(HIT_METRIC)
            .with_description("Certificate chain cache hits")
            .build();
        let miss_counter = meter
            .u64_counter(MISS_METRIC)
            .with_description("Certificate chain cache misses")
            .build();
        let replacement_counter = meter
            .u64_counter(REPLACEMENT_METRIC)
            .with_description("Certificate chain cache replacements (post-provisioning)")
            .build();

        let inner = Cache::builder().max_capacity(CACHE_CAPACITY).build();
        Self {
            inner,
            domain_label: domain.as_ref().to_string(),
            hit_counter,
            miss_counter,
            replacement_counter,
        }
    }

    /// So the series exist in scrapes before the first hit.
    pub(crate) fn init_counters(&self) {
        self.hit_counter.add(0, &self.attributes());
        self.miss_counter.add(0, &self.attributes());
        self.replacement_counter.add(0, &self.attributes());
    }

    pub(crate) async fn get(&self, key: &str) -> Option<CertificateChain> {
        let cached = self.inner.get(key).await;
        if cached.is_some() {
            self.hit_counter.add(1, &self.attributes());
        } else {
            self.miss_counter.add(1, &self.attributes());
        }
        cached
    }

    pub(crate) async fn insert(&self, key: String, value: CertificateChain) {
        self.inner.insert(key, value).await;
    }

    pub(crate) async fn replace(&self, key: String, value: CertificateChain) {
        self.replacement_counter.add(1, &self.attributes());
        self.inner.insert(key, value).await;
    }

    fn attributes(&self) -> Vec<KeyValue> {
        if self.domain_label.is_empty() {
            vec![]
        } else {
            vec![KeyValue::new("domain", self.domain_label.clone())]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{TelemetryConfig, TelemetryEnvironment},
        utils::metrics::{metrics_test_lock, setup_metrics},
    };
    use opentelemetry_sdk::Resource;
    use prometheus::{Encoder, Registry, TextEncoder};

    #[test]
    fn test_counters_are_exported_to_prometheus() {
        let _metrics_guard = metrics_test_lock();
        let registry = Registry::new();
        let config = TelemetryConfig {
            environment: TelemetryEnvironment::Development,
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampler_ratio: 1.0,
            enabled: false,
        };
        let _meter_provider = setup_metrics(
            &registry,
            &config,
            Resource::builder()
                .with_service_name("status-list-server-test")
                .build(),
        )
        .expect("metrics setup");

        let cache = CertChainCache::new("example.com");
        cache.init_counters();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let chain: CertificateChain = Arc::from(vec!["a".to_string()]);
            cache.insert("k".to_string(), chain.clone()).await;

            assert!(cache.get("k").await.is_some());
            assert!(cache.get("missing").await.is_none());
            let new_chain: CertificateChain = Arc::from(vec!["b".to_string()]);
            cache.replace("k".to_string(), new_chain).await;
        });

        assert_counter_value(&registry, HIT_METRIC, 1.0);
        assert_counter_value(&registry, MISS_METRIC, 1.0);
        assert_counter_value(&registry, REPLACEMENT_METRIC, 1.0);
    }

    fn assert_counter_value(registry: &Registry, metric_name: &str, expected: f64) {
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");
        let sample = format!(
            r#"{metric_name}_total{{domain="example.com",otel_scope_name="status-list-server"}} {expected}"#
        );
        assert!(
            body.contains(&sample),
            "missing sample {sample}; body:\n{body}"
        );
    }
}
