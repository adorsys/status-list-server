#[cfg(feature = "redis")]
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use moka::future::Cache as MokaCache;
use opentelemetry::{KeyValue, metrics::Counter};
use std::{num::NonZeroU64, sync::Arc, time::Duration};
#[cfg(feature = "redis")]
use tokio::sync::Mutex;

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
static REDIS_PUT_SCRIPT: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
        local marker = redis.call('GET', KEYS[2])
        local updated_at = tonumber(ARGV[2])
        if marker and updated_at < tonumber(marker) then
            return 0
        end

        local current_updated_at = redis.call('HGET', KEYS[1], 'u')
        if current_updated_at and updated_at < tonumber(current_updated_at) then
            return 0
        end

        redis.call('HSET', KEYS[1], 'v', ARGV[1], 'u', ARGV[2])
        redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
        return 1
        "#,
    )
});

#[cfg(feature = "redis")]
// Committed OCC version markers intentionally have no expiry: a delayed stale read-fill
// must never become cacheable after the record entry expires.
static REDIS_INVALIDATE_SCRIPT: std::sync::LazyLock<redis::Script> =
    std::sync::LazyLock::new(|| {
        redis::Script::new(
            r#"
        redis.call('DEL', KEYS[1])

        local existing_marker = tonumber(redis.call('GET', KEYS[2]))
        local committed_updated_at = tonumber(ARGV[1])
        if not existing_marker or committed_updated_at > existing_marker then
            redis.call('SET', KEYS[2], ARGV[1])
        end
        return 1
        "#,
        )
    });

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

fn cache_attrs(backend: &'static str) -> [KeyValue; 2] {
    [
        KeyValue::new("cache", "status_list"),
        KeyValue::new("backend", backend),
    ]
}

#[cfg(feature = "redis")]
fn cache_error_attrs(backend: &'static str, operation: &'static str) -> [KeyValue; 3] {
    [
        KeyValue::new("cache", "status_list"),
        KeyValue::new("backend", backend),
        KeyValue::new("operation", operation),
    ]
}

#[cfg(feature = "redis")]
pub(crate) fn record_redis_cache_error(operation: &'static str) {
    cache_metrics()
        .errors
        .add(1, &cache_error_attrs("redis", operation));
}

#[cfg(feature = "redis")]
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
    pub fn new(ttl_secs: NonZeroU64, max_capacity: u64) -> Self {
        let inner = MokaCache::builder()
            .time_to_live(Duration::from_secs(ttl_secs.get()))
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

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisStatusListCache {
    client: redis::Client,
    connection: Arc<ArcSwapOption<redis::aio::ConnectionManager>>,
    connect_lock: Arc<Mutex<()>>,
    circuit_open_until: Arc<std::sync::atomic::AtomicU64>,
    ttl_secs: u64,
    key_prefix: String,
    response_timeout: Duration,
    connection_timeout: Duration,
    reconnect_cooldown: Duration,
}

#[cfg(feature = "redis")]
impl RedisStatusListCache {
    pub fn new(
        redis_url: &str,
        ttl_secs: u64,
        key_prefix: impl Into<String>,
        response_timeout: Duration,
        connection_timeout: Duration,
        reconnect_cooldown: Duration,
        ca_cert: Option<Vec<u8>>,
    ) -> Result<Self, StatusListError> {
        let client = if let Some(root_cert) = ca_cert {
            redis::Client::build_with_tls(
                redis_url,
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: Some(root_cert),
                },
            )
        } else {
            redis::Client::open(redis_url)
        }
        .map_err(|error| redis_operation_error("connect", error))?;
        Ok(Self {
            client,
            connection: Arc::new(ArcSwapOption::from(None)),
            connect_lock: Arc::new(Mutex::new(())),
            circuit_open_until: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ttl_secs,
            key_prefix: key_prefix.into(),
            response_timeout,
            connection_timeout,
            reconnect_cooldown,
        })
    }

    pub async fn warm_up(&self) -> Result<(), StatusListError> {
        let _ = self.connection("startup").await?;
        Ok(())
    }

    async fn connection(
        &self,
        operation: &'static str,
    ) -> Result<redis::aio::ConnectionManager, StatusListError> {
        if let Some(connection) = self.connection.load_full() {
            return Ok((*connection).clone());
        }

        let now = current_millis();
        let open_until = self
            .circuit_open_until
            .load(std::sync::atomic::Ordering::Relaxed);
        if now < open_until {
            record_redis_cache_error(operation);
            return Err(redis_circuit_open_error(operation, open_until - now));
        }

        let _guard = self.connect_lock.lock().await;
        if let Some(connection) = self.connection.load_full() {
            return Ok((*connection).clone());
        }

        let manager_config = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(Some(self.response_timeout))
            .set_connection_timeout(Some(self.connection_timeout));
        let connection_result = tokio::time::timeout(
            self.connection_timeout,
            redis::aio::ConnectionManager::new_with_config(self.client.clone(), manager_config),
        )
        .await;
        let connection = match connection_result {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                self.open_circuit();
                return Err(redis_operation_error(operation, error));
            }
            Err(_) => {
                self.open_circuit();
                return Err(redis_timeout_error(operation, self.connection_timeout));
            }
        };
        self.circuit_open_until
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.connection.store(Some(Arc::new(connection.clone())));
        Ok(connection)
    }

    fn key(&self, list_id: &str) -> String {
        format!(
            "{}rec:{{{}}}:{CACHE_SCHEMA_VERSION}",
            self.key_prefix, list_id
        )
    }

    fn marker_key(&self, list_id: &str) -> String {
        format!("{}meta:{{{}}}:updated", self.key_prefix, list_id)
    }

    fn open_circuit(&self) {
        let cooldown_ms = self
            .reconnect_cooldown
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.circuit_open_until.store(
            current_millis().saturating_add(cooldown_ms),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    async fn delete_corrupt_entry(&self, key: &str) -> Result<(), StatusListError> {
        use redis::AsyncCommands;

        let mut connection = self.connection("delete_corrupt").await?;
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
        let key = self.key(list_id);
        let mut connection = self.connection("get").await?;
        let cached: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("v")
            .query_async(&mut connection)
            .await
            .map_err(|error| {
                cache_metrics().misses.add(1, &cache_attrs("redis"));
                redis_operation_error("get", error)
            })?;
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
                        metrics.misses.add(1, &cache_attrs("redis"));
                        return Ok(None);
                    }
                    metrics.hits.add(1, &cache_attrs("redis"));
                    Ok(Some(record))
                }
                Err(error) => {
                    tracing::warn!(
                        list_id = %list_id,
                        error = %error,
                        "discarding undecodable Redis status-list cache entry"
                    );
                    self.delete_corrupt_entry(&key).await?;
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
        let value = serde_json::to_string(&record).map_err(cache_error)?;
        let key = self.key(&record.list_id);
        let marker_key = self.marker_key(&record.list_id);
        let mut connection = self.connection("put").await?;
        let _: i32 = REDIS_PUT_SCRIPT
            .key(key)
            .key(marker_key)
            .arg(value)
            .arg(record.updated_at)
            .arg(self.ttl_secs)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| redis_operation_error("put", error))?;
        Ok(())
    }

    async fn invalidate(&self, list_id: &str) -> Result<(), StatusListError> {
        let mut connection = self.connection("invalidate").await?;
        let _: i32 = redis::cmd("DEL")
            .arg(self.key(list_id))
            .query_async(&mut connection)
            .await
            .map_err(|error| redis_operation_error("invalidate", error))?;
        Ok(())
    }
    async fn invalidate_after_update(
        &self,
        list_id: &str,
        updated_at: i64,
    ) -> Result<(), StatusListError> {
        let mut connection = self.connection("invalidate").await?;
        let _: i32 = REDIS_INVALIDATE_SCRIPT
            .key(self.key(list_id))
            .key(self.marker_key(list_id))
            .arg(updated_at)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| redis_operation_error("invalidate", error))?;
        Ok(())
    }
}

#[cfg(feature = "redis")]
fn current_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(feature = "redis")]
fn redis_error(error: redis::RedisError) -> StatusListError {
    StatusListError::Backend(Box::new(error))
}

#[cfg(feature = "redis")]
fn redis_timeout_error(operation: &'static str, timeout: Duration) -> StatusListError {
    record_redis_cache_error(operation);
    StatusListError::Backend(Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Redis cache {operation} timed out after {timeout:?}"),
    )))
}

#[cfg(feature = "redis")]
fn redis_circuit_open_error(operation: &'static str, remaining_ms: u64) -> StatusListError {
    StatusListError::Backend(Box::new(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        format!("Redis cache {operation} short-circuited for {remaining_ms}ms"),
    )))
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

        let cache = MokaStatusListCache::new(NonZeroU64::new(10).unwrap(), 100);
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

    #[test]
    fn status_list_record_cache_json_shape_is_pinned() {
        let record = StatusListRecord {
            list_id: "shape".into(),
            issuer: Issuer("issuer".into()),
            status_list: StatusList {
                bits: 1,
                lst: "lst".into(),
            },
            sub: "sub".into(),
            updated_at: 42,
        };

        let value = serde_json::to_value(&record).expect("serialize record");
        assert_eq!(
            value,
            serde_json::json!({
                "list_id": "shape",
                "issuer": "issuer",
                "status_list": { "bits": 1, "lst": "lst" },
                "sub": "sub",
                "updated_at": 42
            })
        );
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

    use tokio::sync::OnceCell;

    static REDIS_CONTAINER: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
    static REDIS_TEST_LOCK: Mutex<()> = Mutex::const_new(());

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

    async fn redis_container() -> &'static ContainerAsync<GenericImage> {
        REDIS_CONTAINER
            .get_or_init(|| async {
                GenericImage::new("redis", "8.10-alpine")
                    .with_exposed_port(6379.tcp())
                    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
                    .start()
                    .await
                    .expect("start Redis container")
            })
            .await
    }

    async fn redis_url() -> String {
        if let Ok(redis_url) = std::env::var("TEST_REDIS_URL") {
            return redis_url;
        }

        let node = redis_container().await;
        let host = node.get_host().await.expect("resolve Redis host");
        let port = node
            .get_host_port_ipv4(6379)
            .await
            .expect("resolve Redis port");

        format!("redis://{host}:{port}/0")
    }

    fn redis_cache(redis_url: &str, ttl_secs: u64) -> RedisStatusListCache {
        RedisStatusListCache::new(
            redis_url,
            ttl_secs,
            "status-list-server:test:",
            Duration::from_millis(250),
            Duration::from_millis(250),
            Duration::from_millis(250),
            None,
        )
        .expect("configure redis cache")
    }

    #[tokio::test]
    async fn redis_cache_round_trips_and_invalidates() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);

        let list_id = format!("list-{}", uuid::Uuid::new_v4());
        let record = record(&list_id);
        cache.put(record.clone()).await.expect("put record");
        assert_eq!(cache.get(&list_id).await.expect("get record"), Some(record));

        cache.invalidate(&list_id).await.expect("invalidate record");
        assert_eq!(cache.get(&list_id).await.expect("get invalidated"), None);
    }

    #[tokio::test]
    async fn redis_cache_shared_prefix_invalidation_clears_other_instance() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache_a = redis_cache(&redis_url, 60);
        let cache_b = redis_cache(&redis_url, 60);
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
    async fn redis_cache_durable_marker_survives_entry_expiry_and_rejects_delayed_stale_fill() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 1);
        let list_id = format!("stale-{}", uuid::Uuid::new_v4());

        let updated_at = crate::domain::service::current_unix_timestamp();
        cache
            .put(record_at(&list_id, updated_at))
            .await
            .expect("put stale base");
        cache
            .invalidate_after_update(&list_id, updated_at + 1)
            .await
            .expect("write invalidation marker");
        let mut connection = cache.connection("test").await.expect("connect to Redis");
        let marker_ttl: i64 = redis::cmd("TTL")
            .arg(cache.marker_key(&list_id))
            .query_async(&mut connection)
            .await
            .expect("read invalidation marker TTL");
        assert_eq!(marker_ttl, -1, "version marker must outlive delayed fills");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            cache.get(&list_id).await.expect("cache entry expires"),
            None
        );
        cache
            .put(record_at(&list_id, updated_at))
            .await
            .expect("older fill is ignored, not an error");

        assert_eq!(
            cache.get(&list_id).await.expect("stale fill rejected"),
            None
        );
    }

    #[tokio::test]
    async fn redis_cache_reverse_order_invalidation_keeps_newest_version_fence() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);
        let list_id = format!("reverse-{}", uuid::Uuid::new_v4());
        let now = crate::domain::service::current_unix_timestamp();

        cache
            .invalidate_after_update(&list_id, now + 2)
            .await
            .expect("write newer invalidation marker");
        cache
            .invalidate_after_update(&list_id, now + 1)
            .await
            .expect("write delayed older invalidation marker");
        cache
            .put(record_at(&list_id, now + 1))
            .await
            .expect("older delayed fill is ignored, not an error");

        let mut connection = cache.connection("test").await.expect("connect to Redis");
        let marker: String = redis::cmd("GET")
            .arg(cache.marker_key(&list_id))
            .query_async(&mut connection)
            .await
            .expect("read invalidation marker");
        assert_eq!(marker, (now + 2).to_string());
        assert_eq!(
            cache.get(&list_id).await.expect("delayed fill rejected"),
            None
        );
    }

    #[tokio::test]
    async fn redis_cache_corrupt_entry_is_miss_and_deleted() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);
        let list_id = format!("bad-{}", uuid::Uuid::new_v4());

        let mut connection = cache.connection("test").await.expect("connect to redis");
        let _: () = redis::cmd("HSET")
            .arg(cache.key(&list_id))
            .arg("v")
            .arg("not-json")
            .arg("u")
            .arg(0)
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
    async fn redis_cache_mismatched_list_id_is_miss_and_deleted() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);
        let requested_id = format!("requested-{}", uuid::Uuid::new_v4());
        let wrong_record = record(&format!("other-{}", uuid::Uuid::new_v4()));
        let value = serde_json::to_string(&wrong_record).expect("serialize wrong record");

        let mut connection = cache.connection("test").await.expect("connect to redis");
        let _: () = redis::cmd("HSET")
            .arg(cache.key(&requested_id))
            .arg("v")
            .arg(value)
            .arg("u")
            .arg(wrong_record.updated_at)
            .query_async(&mut connection)
            .await
            .expect("write mismatched entry");

        assert_eq!(
            cache
                .get(&requested_id)
                .await
                .expect("mismatch becomes miss"),
            None
        );
        let exists: bool = redis::cmd("EXISTS")
            .arg(cache.key(&requested_id))
            .query_async(&mut connection)
            .await
            .expect("check mismatched key deleted");
        assert!(!exists);
    }

    #[tokio::test]
    async fn redis_cache_get_times_out_when_server_paused() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        if std::env::var("TEST_REDIS_URL").is_ok() {
            return;
        }
        let container = redis_container().await;
        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);

        container.pause().await.expect("pause redis");
        let result = tokio::time::timeout(Duration::from_secs(1), cache.get("any")).await;
        container.unpause().await.expect("unpause redis");

        assert!(result.is_ok(), "cache get exceeded outer timeout");
        assert!(result.expect("outer timeout result").is_err());
    }

    #[cfg(feature = "memory")]
    #[tokio::test]
    async fn ha_patch_invalidation_blocks_stale_read_fill() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
        use crate::domain::models::status_list::{Status, StatusEntry};
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
                Ok(crate::domain::ports::SigningMaterial::new(
                    None,
                    std::sync::Arc::new(
                        crate::utils::crypto::SigningKey::generate(
                            crate::domain::models::token::SigningAlgorithm::Es256,
                        )
                        .expect("generate test signing key"),
                    ),
                ))
            }
        }

        let redis_url = redis_url().await;
        let cache_a = redis_cache(&redis_url, 60);
        let cache_b = redis_cache(&redis_url, 60);
        let snapshots = MemoryStatusListSnapshotRepo::default();
        let repo = MemoryStatusLists::default().with_snapshot(&snapshots);
        let service_a = Service::new(
            repo.clone(),
            MemoryCredentials::default(),
            cache_a.clone(),
            Some(Arc::new(snapshots.clone())),
            TestCertProvider,
        );
        let service_b = Service::new(
            repo.clone(),
            MemoryCredentials::default(),
            cache_b.clone(),
            Some(Arc::new(snapshots)),
            TestCertProvider,
        );

        let list_id = format!("ha-{}", uuid::Uuid::new_v4());
        let mut old = record_at(&list_id, crate::domain::service::current_unix_timestamp());
        old.status_list = StatusList::create(vec![StatusEntry {
            index: 0,
            status: Status::Valid,
        }])
        .expect("create valid status list");
        service_a
            .status_list_repo()
            .insert(old.clone(), 1_000)
            .await
            .expect("insert backing record");

        assert_eq!(
            service_a
                .get_status_list(&list_id)
                .await
                .expect("reader fill"),
            old
        );

        let updated = service_b
            .update_statuses(
                &old.issuer,
                &list_id,
                vec![StatusEntry {
                    index: 0,
                    status: Status::Invalid,
                }],
                900,
                100_000,
                5_000,
                1_048_576,
            )
            .await
            .expect("patch status list");

        cache_a
            .put(old)
            .await
            .expect("stale read-fill should be ignored, not fail");
        assert_eq!(
            cache_a
                .get(&list_id)
                .await
                .expect("cache after stale fill attempt"),
            None
        );
        assert_eq!(
            service_a
                .get_status_list(&list_id)
                .await
                .expect("reader refetches patched record"),
            updated
        );
    }

    #[cfg(feature = "memory")]
    #[tokio::test]
    async fn service_get_status_list_uses_redis_cache() {
        let _redis_test_lock = REDIS_TEST_LOCK.lock().await;
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
                Ok(crate::domain::ports::SigningMaterial::new(
                    None,
                    std::sync::Arc::new(
                        crate::utils::crypto::SigningKey::generate(
                            crate::domain::models::token::SigningAlgorithm::Es256,
                        )
                        .expect("generate test signing key"),
                    ),
                ))
            }
        }

        let redis_url = redis_url().await;
        let cache = redis_cache(&redis_url, 60);

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
            .insert(saved.clone(), 1_000)
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
