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
    key_prefix: String,
    lru_key: String,
}

#[cfg(feature = "cache-redis")]
impl RedisStatusListCache {
    pub async fn new(
        redis_url: &str,
        ttl_secs: u64,
        max_capacity: u64,
        key_prefix: impl Into<String>,
    ) -> Result<Self, StatusListError> {
        let client = redis::Client::open(redis_url).map_err(redis_error)?;
        let connection = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(redis_error)?;
        let key_prefix = key_prefix.into();
        let lru_key = format!("{key_prefix}__lru");
        Ok(Self {
            connection,
            ttl_secs,
            max_capacity,
            key_prefix,
            lru_key,
        })
    }

    fn key(&self, list_id: &str) -> String {
        format!("{}{}", self.key_prefix, list_id)
    }

    fn recency_score() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as f64
    }

    async fn touch(
        &self,
        connection: &mut redis::aio::ConnectionManager,
        list_id: &str,
    ) -> Result<(), StatusListError> {
        let _: () = redis::cmd("ZADD")
            .arg(&self.lru_key)
            .arg(Self::recency_score())
            .arg(list_id)
            .query_async(connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn evict_if_needed(
        &self,
        connection: &mut redis::aio::ConnectionManager,
    ) -> Result<(), StatusListError> {
        let overflow = redis::cmd("ZCARD")
            .arg(&self.lru_key)
            .query_async::<u64>(connection)
            .await
            .map_err(redis_error)?
            .saturating_sub(self.max_capacity);

        if overflow == 0 {
            return Ok(());
        }

        let victims = redis::cmd("ZRANGE")
            .arg(&self.lru_key)
            .arg(0)
            .arg((overflow - 1) as isize)
            .query_async::<Vec<String>>(connection)
            .await
            .map_err(redis_error)?;

        if victims.is_empty() {
            return Ok(());
        }

        let keys = victims
            .iter()
            .map(|list_id| self.key(list_id))
            .collect::<Vec<_>>();

        let mut pipe = redis::pipe();
        pipe.del(keys).zrem(&self.lru_key, victims);
        pipe.query_async::<()>(connection)
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

        let key = self.key(list_id);
        let mut connection = self.connection.clone();
        let cached: Option<String> = connection.get(key).await.map_err(redis_error)?;
        let metrics = cache_metrics();
        if let Some(value) = cached {
            self.touch(&mut connection, list_id).await?;
            metrics
                .hits
                .add(1, &[KeyValue::new("cache", "status_list")]);
            let record = serde_json::from_str(&value).map_err(cache_error)?;
            Ok(Some(record))
        } else {
            let _: () = redis::cmd("ZREM")
                .arg(&self.lru_key)
                .arg(list_id)
                .query_async(&mut connection)
                .await
                .map_err(redis_error)?;
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
        let value = serde_json::to_string(&record).map_err(cache_error)?;
        let mut connection = self.connection.clone();
        let list_id = record.list_id.clone();
        let mut pipe = redis::pipe();
        pipe.set_ex(key, value, self.ttl_secs)
            .cmd("ZADD")
            .arg(&self.lru_key)
            .arg(Self::recency_score())
            .arg(&list_id);
        pipe.query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        self.evict_if_needed(&mut connection).await?;
        Ok(())
    }

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError> {
        let key = self.key(list_id);
        let mut connection = self.connection.clone();
        let mut pipe = redis::pipe();
        pipe.del(key).zrem(&self.lru_key, list_id);
        pipe.query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
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
#[cfg(feature = "cache-redis")]
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
        let cache = RedisStatusListCache::new(&redis_url, 60, 100, prefix)
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
        let cache = RedisStatusListCache::new(&redis_url, 0, 100, prefix)
            .await
            .expect("connect to redis");

        cache.put(record("list-2")).await.expect("put skipped");
        assert_eq!(cache.get("list-2").await.expect("get skipped"), None);
    }

    #[tokio::test]
    async fn redis_cache_evicts_least_recently_used_record() {
        let (_container, redis_url) = redis_url().await;
        let prefix = format!("status-list-server:test:{}:", uuid::Uuid::new_v4());
        let cache = RedisStatusListCache::new(&redis_url, 60, 2, prefix)
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
}
