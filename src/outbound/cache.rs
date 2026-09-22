//! In-process status-list cache adapter.
use async_trait::async_trait;
use moka::future::Cache as MokaCache;
use opentelemetry::{KeyValue, metrics::Counter};
use std::{sync::Arc, time::Duration};

use crate::domain::{
    models::status_list::{StatusListError, StatusListRecord},
    ports::StatusListCache,
};

const HIT_METRIC: &str = "status_list_cache_hits";
const MISS_METRIC: &str = "status_list_cache_misses";
#[cfg(feature = "redis")]
const ERROR_METRIC: &str = "status_list_cache_errors";
#[cfg(feature = "redis")]
const CACHE_SCHEMA_VERSION: &str = "v1";
#[cfg(feature = "redis")]
const REDIS_KEY_PREFIX: &str = "status-list-server:status-list:";
#[cfg(feature = "redis")]
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(feature = "redis")]
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_millis(250);

/// Cache-hit/miss SLI counters.
///
/// Handles are cached through `cached_instruments`, keyed on the global
/// meter-provider generation, so a fresh provider (e.g. a re-run of
/// `setup_metrics` in tests) never leaves stale no-op handles behind. Unlike an
/// eager `global::meter()` binding at construction, this is robust to the cache
/// being built before `init_telemetry`.
#[derive(Clone)]
struct CacheMetrics {
    hits: Counter<u64>,
    misses: Counter<u64>,
    #[cfg(feature = "redis")]
    errors: Counter<u64>,
}

fn cache_metrics() -> CacheMetrics {
    static METRICS: std::sync::OnceLock<std::sync::Mutex<Option<(u64, CacheMetrics)>>> =
        std::sync::OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = opentelemetry::global::meter("status-list-server");
        CacheMetrics {
            hits: meter
                .u64_counter(HIT_METRIC)
                .with_description("Status-list cache hits")
                .build(),
            misses: meter
                .u64_counter(MISS_METRIC)
                .with_description("Status-list cache misses")
                .build(),
            #[cfg(feature = "redis")]
            errors: meter
                .u64_counter(ERROR_METRIC)
                .with_description("Status-list cache backend errors")
                .build(),
        }
    })
}

#[cfg(feature = "redis")]
fn cache_error_attrs(operation: &'static str) -> [KeyValue; 2] {
    [
        KeyValue::new("cache", "status_list"),
        KeyValue::new("operation", operation),
    ]
}

#[cfg(feature = "redis")]
pub(crate) fn record_redis_cache_error(operation: &'static str) {
    cache_metrics().errors.add(1, &cache_error_attrs(operation));
}

#[cfg(feature = "redis")]
fn redis_operation_error(operation: &'static str, error: redis::RedisError) -> StatusListError {
    record_redis_cache_error(operation);
    StatusListError::Backend(Box::new(error))
}

#[derive(Clone, Default)]
pub struct DisabledStatusListCache;

#[async_trait]
impl StatusListCache for DisabledStatusListCache {
    async fn get(&self, _list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        cache_metrics()
            .misses
            .add(1, &[KeyValue::new("cache", "status_list")]);
        Ok(None)
    }

    async fn put(&self, _status_list: StatusListRecord) -> Result<(), StatusListError> {
        Ok(())
    }

    async fn invalidate(&self, _list_id: &str) -> Result<(), StatusListError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MokaStatusListCache {
    inner: MokaCache<String, Arc<StatusListRecord>>,
}

impl MokaStatusListCache {
    /// Build an in-process cache.
    ///
    /// A `ttl_secs` value of `0` preserves the existing "cache disabled"
    /// behavior: inserted entries expire immediately and reads miss.
    ///
    /// Counter handles are resolved lazily and generation-aware on every read
    /// through `cache_metrics`/`cached_instruments`, so they stay valid
    /// regardless of whether the global meter provider has been installed yet
    /// or has since been replaced (e.g. a re-run of `setup_metrics` in tests).
    pub fn new(ttl_secs: u64, max_capacity: u64) -> Self {
        if ttl_secs == 0 {
            tracing::info!("Cache disabled (TTL=0)");
        }
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        Self { inner }
    }
}

#[async_trait]
impl StatusListCache for MokaStatusListCache {
    async fn get(&self, key: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        let cached = self.inner.get(key).await;
        let metrics = cache_metrics();
        if cached.is_some() {
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "status_list")]);
        } else {
            metrics
                .misses
                .add(1, &[KeyValue::new("cache", "status_list")]);
        }
        Ok(cached.map(|arc| (*arc).clone()))
    }

    async fn put(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        self.inner
            .insert(record.list_id.clone(), Arc::new(record))
            .await;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), StatusListError> {
        self.inner.invalidate(key).await;
        Ok(())
    }
}

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisStatusListCache {
    connection: redis::aio::ConnectionManager,
    ttl_secs: u64,
    record_prefix: String,
}

#[cfg(feature = "redis")]
impl RedisStatusListCache {
    pub async fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, StatusListError> {
        let client = redis::Client::open(redis_url)
            .map_err(|error| redis_operation_error("connect", error))?;
        let manager_config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT)
            .set_connection_timeout(REDIS_CONNECTION_TIMEOUT);
        let connection = redis::aio::ConnectionManager::new_with_config(client, manager_config)
            .await
            .map_err(|error| redis_operation_error("connect", error))?;
        Ok(Self {
            connection,
            ttl_secs,
            record_prefix: format!("{REDIS_KEY_PREFIX}rec:{CACHE_SCHEMA_VERSION}:"),
        })
    }

    fn key(&self, list_id: &str) -> String {
        format!("{}{}", self.record_prefix, list_id)
    }

    async fn delete_corrupt_entry(&self, key: &str) -> Result<(), StatusListError> {
        use redis::AsyncCommands;

        let mut connection = self.connection.clone();
        let _: () = connection
            .del(key)
            .await
            .map_err(|error| redis_operation_error("delete_corrupt", error))?;
        Ok(())
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl StatusListCache for RedisStatusListCache {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        use redis::AsyncCommands;

        if self.ttl_secs == 0 {
            cache_metrics()
                .misses
                .add(1, &[KeyValue::new("cache", "status_list")]);
            return Ok(None);
        }

        let key = self.key(list_id);
        let mut connection = self.connection.clone();
        let cached: Option<String> = connection
            .get(&key)
            .await
            .map_err(|error| redis_operation_error("get", error))?;
        let metrics = cache_metrics();
        if let Some(value) = cached {
            match serde_json::from_str::<StatusListRecord>(&value) {
                Ok(record) => {
                    if record.list_id != list_id {
                        tracing::warn!(
                            requested_list_id = %list_id,
                            cached_list_id = %record.list_id,
                            "discarding Redis status-list cache entry with mismatched list_id"
                        );
                        self.delete_corrupt_entry(&key).await?;
                        metrics
                            .misses
                            .add(1, &[KeyValue::new("cache", "status_list")]);
                        return Ok(None);
                    }
                    metrics
                        .hits
                        .add(1, &[KeyValue::new("cache", "status_list")]);
                    Ok(Some(record))
                }
                Err(error) => {
                    tracing::warn!(
                        list_id = %list_id,
                        error = %error,
                        "discarding undecodable Redis status-list cache entry"
                    );
                    self.delete_corrupt_entry(&key).await?;
                    metrics
                        .misses
                        .add(1, &[KeyValue::new("cache", "status_list")]);
                    Ok(None)
                }
            }
        } else {
            metrics
                .misses
                .add(1, &[KeyValue::new("cache", "status_list")]);
            Ok(None)
        }
    }

    async fn put(&self, record: StatusListRecord) -> Result<(), StatusListError> {
        use redis::AsyncCommands;

        if self.ttl_secs == 0 {
            return Ok(());
        }

        let key = self.key(&record.list_id);
        let value = serde_json::to_string(&record).map_err(cache_error)?;
        let mut connection = self.connection.clone();
        let _: () = connection
            .set_ex(key, value, self.ttl_secs)
            .await
            .map_err(|error| redis_operation_error("put", error))?;
        Ok(())
    }

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError> {
        use redis::AsyncCommands;

        let mut connection = self.connection.clone();
        let _: () = connection
            .del(self.key(list_id))
            .await
            .map_err(|error| redis_operation_error("invalidate", error))?;
        Ok(())
    }
}

#[cfg(feature = "redis")]
fn cache_error(error: serde_json::Error) -> StatusListError {
    StatusListError::Backend(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{TelemetryConfig, TelemetryEnvironment},
        domain::models::credential::Issuer,
        domain::models::status_list::StatusList,
        utils::metrics::{metrics_test_lock, setup_metrics},
    };
    use opentelemetry_sdk::Resource;
    use prometheus::{Encoder, Registry, TextEncoder};

    #[tokio::test]
    async fn ttl_zero_expires_entries_immediately() {
        let cache = MokaStatusListCache::new(0, 10);
        cache
            .put(StatusListRecord {
                list_id: "id".into(),
                issuer: Issuer("issuer".into()),
                status_list: StatusList {
                    bits: 1,
                    lst: "lst".into(),
                },
                sub: "sub".into(),
                updated_at: 0,
            })
            .await
            .unwrap();

        assert!(cache.get("id").await.unwrap().is_none());
    }

    #[test]
    fn cache_counts_hits_and_misses_are_exported() {
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

        let cache = MokaStatusListCache::new(10, 100);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let record = StatusListRecord {
                list_id: "k".into(),
                issuer: Issuer("issuer".into()),
                status_list: StatusList {
                    bits: 1,
                    lst: "lst".into(),
                },
                sub: "sub".into(),
                updated_at: 0,
            };
            cache.put(record).await.unwrap();
            assert!(cache.get("k").await.unwrap().is_some());
            assert!(cache.get("missing").await.unwrap().is_none());
        });

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .expect("encode metrics");
        let body = String::from_utf8(buffer).expect("metrics are valid UTF-8");

        for metric in [HIT_METRIC, MISS_METRIC] {
            let metric_prefix = format!(
                r#"{metric}_total{{cache="status_list",otel_scope_name="status-list-server"}}"#
            );
            assert!(
                body.contains(&metric_prefix),
                "missing metric series {metric_prefix}; body:\n{body}"
            );
        }
    }
}
