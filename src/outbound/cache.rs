//! Status-list cache adapters.
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
#[cfg(feature = "cache-redis")]
const ERROR_METRIC: &str = "status_list_cache_errors";
#[cfg(feature = "cache-redis")]
const CACHE_SCHEMA_VERSION: &str = "v1";
#[cfg(feature = "cache-redis")]
const REDIS_KEY_PREFIX: &str = "status-list-server:status-list:";
#[cfg(feature = "cache-redis")]
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(feature = "cache-redis")]
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
    #[cfg(feature = "cache-redis")]
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
            #[cfg(feature = "cache-redis")]
            errors: meter
                .u64_counter(ERROR_METRIC)
                .with_description("Status-list cache backend errors")
                .build(),
        }
    })
}

fn cache_attrs(backend: &'static str) -> [KeyValue; 2] {
    [
        KeyValue::new("cache", "status_list"),
        KeyValue::new("backend", backend),
    ]
}

#[cfg(feature = "cache-redis")]
fn cache_error_attrs(backend: &'static str, operation: &'static str) -> [KeyValue; 3] {
    [
        KeyValue::new("cache", "status_list"),
        KeyValue::new("backend", backend),
        KeyValue::new("operation", operation),
    ]
}

#[cfg(feature = "cache-redis")]
pub(crate) fn record_redis_cache_error(operation: &'static str) {
    cache_metrics()
        .errors
        .add(1, &cache_error_attrs("redis", operation));
}

#[cfg(feature = "cache-redis")]
fn redis_operation_error(operation: &'static str, error: redis::RedisError) -> StatusListError {
    record_redis_cache_error(operation);
    redis_error(error)
}

#[derive(Clone, Default)]
pub struct DisabledStatusListCache;

#[async_trait]
impl StatusListCache for DisabledStatusListCache {
    async fn get(&self, _list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        cache_metrics().misses.add(1, &cache_attrs("disabled"));
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
            metrics.hits.add(1, &cache_attrs("memory"));
        } else {
            metrics.misses.add(1, &cache_attrs("memory"));
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

#[cfg(feature = "cache-redis")]
#[derive(Clone)]
pub struct RedisStatusListCache {
    connection: redis::aio::ConnectionManager,
    ttl_secs: u64,
    record_prefix: String,
}

#[cfg(feature = "cache-redis")]
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
        let record_prefix = format!("{REDIS_KEY_PREFIX}rec:{CACHE_SCHEMA_VERSION}:");
        Ok(Self {
            connection,
            ttl_secs,
            record_prefix,
        })
    }

    fn key(&self, list_id: &str) -> String {
        format!("{}{}", self.record_prefix, list_id)
    }
}

#[cfg(feature = "cache-redis")]
#[async_trait]
impl StatusListCache for RedisStatusListCache {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        use redis::AsyncCommands;

        if self.ttl_secs == 0 {
            cache_metrics().misses.add(1, &cache_attrs("redis"));
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
            match serde_json::from_str(&value) {
                Ok(record) => {
                    metrics.hits.add(1, &cache_attrs("redis"));
                    Ok(Some(record))
                }
                Err(error) => {
                    tracing::warn!(
                        list_id = %list_id,
                        error = %error,
                        "discarding undecodable Redis status-list cache entry"
                    );
                    let _: () = connection
                        .del(&key)
                        .await
                        .map_err(|error| redis_operation_error("delete_corrupt", error))?;
                    metrics.misses.add(1, &cache_attrs("redis"));
                    Ok(None)
                }
            }
        } else {
            metrics.misses.add(1, &cache_attrs("redis"));
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

#[cfg(feature = "cache-redis")]
fn redis_error(error: redis::RedisError) -> StatusListError {
    StatusListError::Backend(Box::new(error))
}

#[cfg(feature = "cache-redis")]
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
                r#"{metric}_total{{backend="memory",cache="status_list",otel_scope_name="status-list-server"}}"#
            );
            assert!(
                body.contains(&metric_prefix),
                "missing metric series {metric_prefix}; body:\n{body}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "redis-tests")]
mod redis_tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::domain::models::status_list::StatusList;
    use testcontainers_modules::testcontainers::{
        ContainerAsync, GenericImage,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };

    fn record_at(list_id: &str, updated_at: i64) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: Issuer("issuer".into()),
            status_list: StatusList {
                bits: 1,
                lst: "lst".into(),
            },
            sub: "sub".into(),
            updated_at,
        }
    }

    fn record(list_id: &str) -> StatusListRecord {
        record_at(list_id, 0)
    }

    async fn redis_url() -> (Option<ContainerAsync<GenericImage>>, String) {
        if let Ok(redis_url) = std::env::var("TEST_REDIS_URL") {
            return (None, redis_url);
        }

        let node = GenericImage::new("redis", "8.4-alpine")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .expect("start Redis container");
        let host = node.get_host().await.expect("resolve Redis host");
        let port = node
            .get_host_port_ipv4(6379)
            .await
            .expect("resolve Redis port");

        (Some(node), format!("redis://{host}:{port}/0"))
    }

    #[tokio::test]
    async fn redis_cache_round_trips_and_invalidates() {
        let (_container, redis_url) = redis_url().await;
        let cache = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect to redis");

        let list_id = format!("list-{}", uuid::Uuid::new_v4());
        let record = record(&list_id);
        cache.put(record.clone()).await.expect("put record");
        assert_eq!(cache.get(&list_id).await.expect("get record"), Some(record));

        cache.invalidate(&list_id).await.expect("invalidate record");
        assert_eq!(cache.get(&list_id).await.expect("get invalidated"), None);
    }

    #[tokio::test]
    async fn redis_cache_ttl_zero_disables_puts() {
        let (_container, redis_url) = redis_url().await;
        let cache = RedisStatusListCache::new(&redis_url, 0)
            .await
            .expect("connect to redis");

        let list_id = format!("disabled-{}", uuid::Uuid::new_v4());
        cache.put(record(&list_id)).await.expect("put skipped");
        assert_eq!(cache.get(&list_id).await.expect("get skipped"), None);
    }

    #[tokio::test]
    async fn redis_cache_shared_prefix_invalidation_clears_other_instance() {
        let (_container, redis_url) = redis_url().await;
        let cache_a = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect cache a");
        let cache_b = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect cache b");
        let list_id = format!("shared-{}", uuid::Uuid::new_v4());

        cache_a.put(record(&list_id)).await.expect("put shared");
        assert!(
            cache_b
                .get(&list_id)
                .await
                .expect("cross-instance get")
                .is_some()
        );

        cache_b
            .invalidate(&list_id)
            .await
            .expect("invalidate from peer");
        assert_eq!(cache_a.get(&list_id).await.expect("invalidated"), None);
    }

    #[tokio::test]
    async fn redis_cache_corrupt_entry_is_miss_and_deleted() {
        let (_container, redis_url) = redis_url().await;
        let cache = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect to redis");
        let list_id = format!("bad-{}", uuid::Uuid::new_v4());

        let mut connection = cache.connection.clone();
        let _: () = redis::cmd("SET")
            .arg(cache.key(&list_id))
            .arg("not-json")
            .query_async(&mut connection)
            .await
            .expect("write corrupt entry");

        assert_eq!(
            cache.get(&list_id).await.expect("corrupt becomes miss"),
            None
        );
        let exists: bool = redis::cmd("EXISTS")
            .arg(cache.key(&list_id))
            .query_async(&mut connection)
            .await
            .expect("check corrupt key deleted");
        assert!(!exists);
    }

    #[tokio::test]
    async fn redis_cache_get_times_out_when_server_paused() {
        let (container, redis_url) = redis_url().await;
        let Some(container) = container else {
            return;
        };
        let cache = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect to redis");

        container.pause().await.expect("pause redis");
        let result = tokio::time::timeout(Duration::from_secs(1), cache.get("any")).await;
        container.unpause().await.expect("unpause redis");

        assert!(result.is_ok(), "cache get exceeded outer timeout");
        assert!(result.expect("outer timeout result").is_err());
    }

    #[cfg(feature = "memory")]
    #[tokio::test]
    async fn service_get_status_list_uses_redis_cache() {
        use crate::domain::ports::CertificateProvider;
        use crate::domain::service::Service;
        use crate::outbound::memory::{
            MemoryCredentials, MemoryStatusListSnapshotRepo, MemoryStatusLists,
        };

        struct TestCertProvider;

        #[async_trait]
        impl CertificateProvider for TestCertProvider {
            async fn signing_material(
                &self,
            ) -> Result<crate::domain::ports::SigningMaterial, StatusListError> {
                Ok(crate::domain::ports::SigningMaterial {
                    certificate_chain: None,
                    signing_key_pem: String::new(),
                })
            }
        }

        let (_container, redis_url) = redis_url().await;
        let cache = RedisStatusListCache::new(&redis_url, 60)
            .await
            .expect("connect to redis");

        let snapshots = MemoryStatusListSnapshotRepo::default();
        let repo = MemoryStatusLists::default().with_snapshot(&snapshots);
        let service = Service::new(
            repo,
            MemoryCredentials::default(),
            cache.clone(),
            Some(Arc::new(snapshots)),
            TestCertProvider,
        );
        let saved = record("service-list");
        service
            .status_list_repo()
            .insert(saved.clone())
            .await
            .expect("insert backing record");

        assert_eq!(
            service
                .get_status_list("service-list")
                .await
                .expect("service get"),
            saved
        );
        assert!(
            cache
                .get("service-list")
                .await
                .expect("redis populated")
                .is_some()
        );
    }
}
