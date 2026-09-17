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
const CACHE_SCHEMA_VERSION: &str = "v1";

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
        }
    })
}

#[derive(Clone, Default)]
pub struct DisabledStatusListCache;

#[async_trait]
impl StatusListCache for DisabledStatusListCache {
    async fn get(&self, _list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
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

#[cfg(feature = "cache-redis")]
#[derive(Clone)]
pub struct RedisStatusListCache {
    connection: redis::aio::ConnectionManager,
    ttl_secs: u64,
    max_capacity: u64,
    lru_key: String,
    record_prefix: String,
    marker_prefix: String,
}

#[cfg(feature = "cache-redis")]
impl RedisStatusListCache {
    pub async fn new(
        redis_url: &str,
        ttl_secs: u64,
        max_capacity: u64,
        key_prefix: impl Into<String>,
        response_timeout: Duration,
        connection_timeout: Duration,
    ) -> Result<Self, StatusListError> {
        let client = redis::Client::open(redis_url).map_err(redis_error)?;
        let manager_config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(response_timeout)
            .set_connection_timeout(connection_timeout);
        let connection = redis::aio::ConnectionManager::new_with_config(client, manager_config)
            .await
            .map_err(redis_error)?;
        let key_prefix = key_prefix.into();
        let record_prefix = format!("{key_prefix}rec:{CACHE_SCHEMA_VERSION}:");
        let marker_prefix = format!("{key_prefix}meta:{CACHE_SCHEMA_VERSION}:updated:");
        let lru_key = format!("{key_prefix}meta:{CACHE_SCHEMA_VERSION}:lru");
        Ok(Self {
            connection,
            ttl_secs,
            max_capacity,
            lru_key,
            record_prefix,
            marker_prefix,
        })
    }

    fn key(&self, list_id: &str) -> String {
        format!("{}{}", self.record_prefix, list_id)
    }

    fn marker_key(&self, list_id: &str) -> String {
        format!("{}{}", self.marker_prefix, list_id)
    }

    async fn touch(
        &self,
        connection: &mut redis::aio::ConnectionManager,
        list_id: &str,
    ) -> Result<(), StatusListError> {
        if self.ttl_secs == 0 || self.max_capacity == 0 {
            return Ok(());
        }

        let _: () = redis::cmd("EVAL")
            .arg(
                r#"
                local now = redis.call('TIME')
                local score = tonumber(now[1]) * 1000000 + tonumber(now[2])
                redis.call('ZADD', KEYS[1], score, ARGV[1])
                return 1
                "#,
            )
            .arg(1)
            .arg(&self.lru_key)
            .arg(list_id)
            .query_async(connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn delete_corrupt_entry(
        &self,
        connection: &mut redis::aio::ConnectionManager,
        list_id: &str,
    ) -> Result<(), StatusListError> {
        let _: () = redis::cmd("EVAL")
            .arg(
                r#"
                redis.call('DEL', KEYS[1])
                redis.call('ZREM', KEYS[2], ARGV[1])
                return 1
                "#,
            )
            .arg(2)
            .arg(self.key(list_id))
            .arg(&self.lru_key)
            .arg(list_id)
            .query_async(connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn invalidate_with_marker(
        &self,
        list_id: &str,
        updated_at: Option<i64>,
    ) -> Result<(), StatusListError> {
        if self.ttl_secs == 0 || self.max_capacity == 0 {
            return Ok(());
        }

        let mut connection = self.connection.clone();
        let _: () = redis::cmd("EVAL")
            .arg(
                r#"
                redis.call('DEL', KEYS[1])
                redis.call('ZREM', KEYS[2], ARGV[1])
                if ARGV[2] ~= '' then
                    redis.call('SET', KEYS[3], ARGV[2], 'EX', tonumber(ARGV[3]))
                end
                return 1
                "#,
            )
            .arg(3)
            .arg(self.key(list_id))
            .arg(&self.lru_key)
            .arg(self.marker_key(list_id))
            .arg(list_id)
            .arg(
                updated_at
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            )
            .arg(self.ttl_secs)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }
}

#[cfg(feature = "cache-redis")]
#[async_trait]
impl StatusListCache for RedisStatusListCache {
    async fn get(&self, list_id: &str) -> Result<Option<StatusListRecord>, StatusListError> {
        use redis::AsyncCommands;

        if self.ttl_secs == 0 || self.max_capacity == 0 {
            return Ok(None);
        }

        let key = self.key(list_id);
        let mut connection = self.connection.clone();
        let cached: Option<String> = connection.get(key).await.map_err(redis_error)?;
        let metrics = cache_metrics();
        if let Some(value) = cached {
            match serde_json::from_str(&value) {
                Ok(record) => {
                    self.touch(&mut connection, list_id).await?;
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
                    self.delete_corrupt_entry(&mut connection, list_id).await?;
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
        if self.ttl_secs == 0 || self.max_capacity == 0 {
            return Ok(());
        }

        let key = self.key(&record.list_id);
        let marker_key = self.marker_key(&record.list_id);
        let value = serde_json::to_string(&record).map_err(cache_error)?;
        let mut connection = self.connection.clone();
        let list_id = record.list_id.clone();
        let _: () = redis::cmd("EVAL")
            .arg(
                r#"
                local ttl = tonumber(ARGV[2])
                local max_capacity = tonumber(ARGV[3])
                local updated_at = tonumber(ARGV[5])
                if ttl <= 0 or max_capacity <= 0 then
                    return 0
                end

                local marker = redis.call('GET', KEYS[3])
                if marker and updated_at < tonumber(marker) then
                    return 0
                end

                redis.call('SET', KEYS[1], ARGV[6], 'EX', ttl)
                redis.call('SET', KEYS[3], ARGV[5], 'EX', ttl)

                local now = redis.call('TIME')
                local score = tonumber(now[1]) * 1000000 + tonumber(now[2])
                redis.call('ZADD', KEYS[2], score, ARGV[4])

                local overflow = redis.call('ZCARD', KEYS[2]) - max_capacity
                if overflow > 0 then
                    local victims = redis.call('ZRANGE', KEYS[2], 0, overflow - 1)
                    for _, victim in ipairs(victims) do
                        redis.call('DEL', ARGV[1] .. victim)
                        redis.call('ZREM', KEYS[2], victim)
                    end
                end
                return 1
                "#,
            )
            .arg(3)
            .arg(key)
            .arg(&self.lru_key)
            .arg(marker_key)
            .arg(&self.record_prefix)
            .arg(self.ttl_secs)
            .arg(self.max_capacity)
            .arg(&list_id)
            .arg(record.updated_at)
            .arg(value)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError> {
        self.invalidate_with_marker(list_id, None).await
    }

    async fn invalidate_after_update(
        &self,
        list_id: &str,
        updated_at: i64,
    ) -> Result<(), StatusListError> {
        self.invalidate_with_marker(list_id, Some(updated_at)).await
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
                r#"{metric}_total{{cache="status_list",otel_scope_name="status-list-server"}}"#
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

    fn record(list_id: &str) -> StatusListRecord {
        StatusListRecord {
            list_id: list_id.to_string(),
            issuer: Issuer("issuer".into()),
            status_list: StatusList {
                bits: 1,
                lst: "lst".into(),
            },
            sub: "sub".into(),
            updated_at: 0,
        }
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
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect to redis");

        let record = record("list-1");
        cache.put(record.clone()).await.expect("put record");
        assert_eq!(cache.get("list-1").await.expect("get record"), Some(record));

        cache.invalidate("list-1").await.expect("invalidate record");
        assert_eq!(cache.get("list-1").await.expect("get invalidated"), None);
    }

    #[tokio::test]
    async fn redis_cache_ttl_zero_disables_puts() {
        let (_container, redis_url) = redis_url().await;
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            0,
            100,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect to redis");

        cache.put(record("list-2")).await.expect("put skipped");
        assert_eq!(cache.get("list-2").await.expect("get skipped"), None);
    }

    #[tokio::test]
    async fn redis_cache_evicts_least_recently_used_record() {
        let (_container, redis_url) = redis_url().await;
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            2,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect to redis");

        cache.put(record("a")).await.expect("put a");
        tokio::time::sleep(Duration::from_millis(2)).await;
        cache.put(record("b")).await.expect("put b");
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(cache.get("a").await.expect("touch a").is_some());
        tokio::time::sleep(Duration::from_millis(2)).await;
        cache.put(record("c")).await.expect("put c");

        assert!(cache.get("a").await.expect("get a").is_some());
        assert_eq!(cache.get("b").await.expect("b was evicted"), None);
        assert!(cache.get("c").await.expect("get c").is_some());
    }

    #[tokio::test]
    async fn redis_cache_shared_prefix_invalidation_clears_other_instance() {
        let (_container, redis_url) = redis_url().await;
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache_a = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix.clone(),
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect cache a");
        let cache_b = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect cache b");

        cache_a.put(record("shared")).await.expect("put shared");
        assert!(
            cache_b
                .get("shared")
                .await
                .expect("cross-instance get")
                .is_some()
        );

        cache_b
            .invalidate_after_update("shared", 2)
            .await
            .expect("invalidate from peer");
        assert_eq!(cache_a.get("shared").await.expect("invalidated"), None);
    }

    #[tokio::test]
    async fn redis_cache_corrupt_entry_is_miss_and_deleted() {
        let (_container, redis_url) = redis_url().await;
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect to redis");

        let mut connection = cache.connection.clone();
        let _: () = redis::cmd("SET")
            .arg(cache.key("bad"))
            .arg("not-json")
            .query_async(&mut connection)
            .await
            .expect("write corrupt entry");

        assert_eq!(cache.get("bad").await.expect("corrupt becomes miss"), None);
        let exists: bool = redis::cmd("EXISTS")
            .arg(cache.key("bad"))
            .query_async(&mut connection)
            .await
            .expect("check corrupt key deleted");
        assert!(!exists);
    }

    #[tokio::test]
    async fn redis_cache_max_capacity_zero_skips_redis() {
        let (_container, redis_url) = redis_url().await;
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            0,
            format!("status-list-server:test:{}:", uuid::Uuid::new_v4()),
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
        .await
        .expect("connect to redis");

        cache.put(record("disabled")).await.expect("put skipped");
        assert_eq!(cache.get("disabled").await.expect("get skipped"), None);
    }

    #[tokio::test]
    async fn redis_cache_get_times_out_when_server_paused() {
        let (container, redis_url) = redis_url().await;
        let Some(container) = container else {
            return;
        };
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix,
            Duration::from_millis(100),
            Duration::from_millis(100),
        )
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
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(
            &redis_url,
            60,
            100,
            prefix,
            Duration::from_millis(250),
            Duration::from_millis(250),
        )
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
