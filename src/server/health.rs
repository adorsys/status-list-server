//! Liveness and readiness HTTP endpoints plus the small readiness-check
//! abstraction they rely on.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::server::AppState;

const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_CACHE_TTL: Duration = Duration::from_secs(1);

/// A single, independent readiness probe.
///
/// `#[async_trait]` matches the rest of the codebase's port/adaptor trait style
/// (see `domain/ports.rs`). Implementations are constructed in the composition
/// root (`setup.rs`) from the same adapters the application already uses.
#[async_trait::async_trait]
pub trait ReadinessCheck: Send + Sync {
    /// Human-readable name for logging and the readiness body.
    fn name(&self) -> &'static str;

    /// Returns `Ok(())` when the dependency is reachable and the service can
    /// function without it; otherwise `Err(reason)` describing the failure.
    async fn check(&self) -> Result<(), String>;
}

/// Aggregator that runs all registered readiness checks concurrently.
#[derive(Clone, Default)]
pub struct Readiness {
    checks: Vec<Arc<dyn ReadinessCheck>>,
    cache: Arc<Mutex<Option<CachedReadinessReport>>>,
}

#[derive(Clone)]
struct CachedReadinessReport {
    report: ReadinessReport,
    checked_at: Instant,
}

impl std::fmt::Debug for Readiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Readiness")
            .field("check_count", &self.checks.len())
            .finish()
    }
}

impl Readiness {
    /// Build from an explicit list of checks.
    pub fn new(checks: Vec<Arc<dyn ReadinessCheck>>) -> Self {
        Self {
            checks,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Register a single check.
    pub fn with_check<T: ReadinessCheck + 'static>(mut self, check: T) -> Self {
        self.checks.push(Arc::new(check));
        self.cache = Arc::new(Mutex::new(None));
        self
    }

    /// Run every check concurrently and report per-dependency results.
    ///
    /// Each check runs under a timeout so a hung dependency cannot block the
    /// readiness probe forever.
    pub async fn run(&self) -> ReadinessReport {
        let mut cached = self.cache.lock().await;
        if let Some(cached_report) = cached.as_ref()
            && cached_report.checked_at.elapsed() < READINESS_CACHE_TTL
        {
            return cached_report.report.clone();
        }

        let mut set = tokio::task::JoinSet::new();
        for check in &self.checks {
            let check = check.clone();
            set.spawn(async move {
                let res = tokio::time::timeout(CHECK_TIMEOUT, check.check()).await;

                let result = match res {
                    Ok(result) => result,
                    Err(_) => Err("readiness check timed out".to_string()),
                };
                (check, result)
            });
        }

        let mut checks: Vec<CheckResult> = Vec::with_capacity(self.checks.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((check, res)) => checks.push(CheckResult {
                    name: check.name().to_string(),
                    ok: res.is_ok(),
                    reason: res.err(),
                }),
                Err(err) => checks.push(CheckResult {
                    name: "readiness_check_task".to_string(),
                    ok: false,
                    reason: Some(format!("readiness check task failed: {err}")),
                }),
            }
        }

        let ready = checks.len() == self.checks.len() && checks.iter().all(|c| c.ok);
        let report = ReadinessReport { ready, checks };
        *cached = Some(CachedReadinessReport {
            report: report.clone(),
            checked_at: Instant::now(),
        });
        report
    }
}

/// Serialized outcome of running every readiness check.
#[derive(Clone, Debug, Serialize)]
pub struct ReadinessReport {
    ready: bool,
    checks: Vec<CheckResult>,
}

/// Outcome of a single readiness check.
#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Liveness: the HTTP process is up and able to serve requests. Deliberately
/// does not depend on any downstream dependency so a healthy process is never
/// restarted merely because a dependency is down.
pub async fn live() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Readiness: `200` only when every critical dependency is reachable, else
/// `503`. Detailed dependency failures are logged internally instead of being
/// exposed in the unauthenticated HTTP response.
pub async fn ready(State(state): State<AppState>) -> Response {
    let report = state.readiness.run().await;
    if report.ready {
        (StatusCode::OK, "READY").into_response()
    } else {
        tracing::warn!(checks = ?report.checks, "readiness check failed");
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY").into_response()
    }
}

/// A readiness check that is always ready (used for in-memory backends).
pub struct AlwaysReady {
    name: &'static str,
}

impl AlwaysReady {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[async_trait::async_trait]
impl ReadinessCheck for AlwaysReady {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Readiness check for a relational database backend.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub struct DbCheck {
    db: std::sync::Arc<sea_orm::DatabaseConnection>,
}

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
impl DbCheck {
    pub fn new(db: std::sync::Arc<sea_orm::DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
#[async_trait::async_trait]
impl ReadinessCheck for DbCheck {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn check(&self) -> Result<(), String> {
        self.db
            .ping()
            .await
            .map_err(|e| format!("database unreachable: {e}"))
    }
}

/// Readiness check for the certificate/key store backend used by the ACME
/// certificate manager. Only verifies reachability — it never reads or parses
/// the private signing key.
#[cfg(feature = "acme")]
pub struct CertStoreCheck {
    manager: std::sync::Arc<crate::utils::cert_manager::CertManager>,
}

#[cfg(feature = "acme")]
impl CertStoreCheck {
    pub fn new(manager: std::sync::Arc<crate::utils::cert_manager::CertManager>) -> Self {
        Self { manager }
    }
}

#[cfg(feature = "acme")]
#[async_trait::async_trait]
impl ReadinessCheck for CertStoreCheck {
    fn name(&self) -> &'static str {
        "cert_store"
    }

    async fn check(&self) -> Result<(), String> {
        let crypto_store = self
            .manager
            .crypto_storage()
            .map_err(|e| format!("cryptographic-material backend not configured: {e}"))?;
        crypto_store
            .reachable()
            .await
            .map_err(|e| format!("cryptographic-material backend unreachable: {e}"))
    }
}

/// Readiness check for the filesystem certificate/key store used when the ACME
/// feature is disabled. Verifies the configured files exist *and* are readable —
/// it never parses the private signing key.
#[cfg(not(feature = "acme"))]
pub struct FilesystemCertCheck {
    cert_path: Option<String>,
    key_path: Option<String>,
}

#[cfg(not(feature = "acme"))]
impl FilesystemCertCheck {
    pub fn new(cert_path: Option<String>, key_path: Option<String>) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }
}

#[cfg(not(feature = "acme"))]
#[async_trait::async_trait]
impl ReadinessCheck for FilesystemCertCheck {
    fn name(&self) -> &'static str {
        "cert_store"
    }

    async fn check(&self) -> Result<(), String> {
        for path in self.cert_path.iter().chain(self.key_path.iter()) {
            tokio::fs::metadata(path)
                .await
                .map_err(|e| format!("cert store file '{path}' unavailable: {e}"))?;
            tokio::fs::OpenOptions::new()
                .read(true)
                .open(path)
                .await
                .map_err(|e| format!("cert store file '{path}' not readable: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "acme")]
    use crate::{
        cert_manager::storage::{Storage, StorageError},
        utils::cert_manager::CertManager,
    };
    #[cfg(feature = "acme")]
    use async_trait::async_trait;
    use axum::body::to_bytes;
    #[cfg(feature = "acme")]
    use std::sync::Once;
    use tower::ServiceExt;

    #[cfg(feature = "acme")]
    static INIT_CRYPTO: Once = Once::new();

    #[cfg(feature = "acme")]
    fn init_crypto() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    struct FailingCheck;

    #[async_trait::async_trait]
    impl ReadinessCheck for FailingCheck {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn check(&self) -> Result<(), String> {
            Err("boom".to_string())
        }
    }

    struct PanickingCheck;

    #[async_trait::async_trait]
    impl ReadinessCheck for PanickingCheck {
        fn name(&self) -> &'static str {
            "panicking"
        }

        async fn check(&self) -> Result<(), String> {
            panic!("boom")
        }
    }

    #[tokio::test]
    async fn readiness_ready_when_all_checks_pass() {
        let readiness = Readiness::default()
            .with_check(AlwaysReady::new("a"))
            .with_check(AlwaysReady::new("b"));
        let report = readiness.run().await;
        assert!(report.ready);
        assert!(report.checks.iter().all(|c| c.ok));
    }

    #[tokio::test]
    async fn readiness_not_ready_when_any_check_fails() {
        let readiness = Readiness::default()
            .with_check(AlwaysReady::new("a"))
            .with_check(FailingCheck)
            .with_check(AlwaysReady::new("b"));
        let report = readiness.run().await;
        assert!(!report.ready);
        assert_eq!(report.checks.len(), 3);
        let failing = report.checks.iter().find(|c| c.name == "failing").unwrap();
        assert!(!failing.ok);
        assert_eq!(failing.reason.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn readiness_not_ready_when_a_check_panics() {
        let readiness = Readiness::default()
            .with_check(AlwaysReady::new("a"))
            .with_check(PanickingCheck)
            .with_check(AlwaysReady::new("b"));
        let report = readiness.run().await;

        assert!(!report.ready);
        assert_eq!(report.checks.len(), 3);
        let panicking = report
            .checks
            .iter()
            .find(|c| c.name == "readiness_check_task")
            .unwrap();
        assert!(!panicking.ok);
        assert!(
            panicking
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("panicked"))
        );
    }

    /// Simulates a specific dependency being unreachable, so each readiness
    /// dependency's failure can be exercised independently.
    struct FailingNamedCheck {
        name: &'static str,
    }

    #[async_trait::async_trait]
    impl ReadinessCheck for FailingNamedCheck {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn check(&self) -> Result<(), String> {
            Err(format!("{} unreachable", self.name))
        }
    }

    /// Build an `AppState` whose readiness is backed only by the supplied checks.
    async fn app_state_with_checks(checks: Vec<Arc<dyn ReadinessCheck>>) -> AppState {
        let mut state = crate::test_utils::test_app_state(None).await;
        state.readiness = Readiness::new(checks);
        state
    }

    async fn call_handler(state: AppState, path: &'static str) -> Response {
        axum::Router::new()
            .route("/health", axum::routing::get(live))
            .route("/health/live", axum::routing::get(live))
            .route("/health/ready", axum::routing::get(ready))
            .with_state(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn response_body(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("read response body");
        String::from_utf8(bytes.to_vec()).expect("health response is utf-8")
    }

    #[tokio::test]
    async fn live_returns_200_while_process_is_up() {
        let state =
            app_state_with_checks(vec![Arc::new(FailingNamedCheck { name: "database" })]).await;
        let resp = call_handler(state, "/health/live").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_alias_returns_200_while_process_is_up() {
        let state =
            app_state_with_checks(vec![Arc::new(FailingNamedCheck { name: "database" })]).await;
        let resp = call_handler(state, "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_body(resp).await, "OK");
    }

    #[tokio::test]
    async fn ready_returns_200_when_all_critical_dependencies_reachable() {
        let state = app_state_with_checks(vec![
            Arc::new(AlwaysReady::new("database")),
            Arc::new(AlwaysReady::new("cert_store")),
        ])
        .await;
        let resp = call_handler(state, "/health/ready").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_body(resp).await, "READY");
    }

    /// Each readiness dependency failure must flip `/health/ready` to 503.
    #[tokio::test]
    async fn ready_fails_when_any_dependency_is_down() {
        for dep in ["database", "cert_store"] {
            let state =
                app_state_with_checks(vec![Arc::new(FailingNamedCheck { name: dep })]).await;
            let resp = call_handler(state, "/health/ready").await;
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "readiness should fail when {dep} is down"
            );
            assert_eq!(response_body(resp).await, "NOT_READY");
        }
    }

    #[cfg(feature = "acme")]
    #[derive(Clone)]
    struct ReachabilityStorage {
        reachable: bool,
    }

    #[cfg(feature = "acme")]
    impl ReachabilityStorage {
        fn unreachable() -> Self {
            Self { reachable: false }
        }
    }

    #[cfg(feature = "acme")]
    #[async_trait]
    impl Storage for ReachabilityStorage {
        async fn store(&self, _key: &str, _value: &str) -> Result<(), StorageError> {
            Ok(())
        }

        async fn load(&self, _key: &str) -> Result<Option<String>, StorageError> {
            Ok(None)
        }

        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            Ok(())
        }

        async fn reachable(&self) -> Result<(), StorageError> {
            if self.reachable {
                Ok(())
            } else {
                Err(StorageError::InvalidData("unreachable".to_string()))
            }
        }
    }

    #[cfg(feature = "acme")]
    #[tokio::test]
    async fn ready_fails_when_crypto_material_backend_is_unreachable() {
        init_crypto();

        let manager = CertManager::new(
            ["example.com"],
            "test@example.com",
            Option::<String>::None,
            "https://acme.example.com/directory",
        )
        .expect("build cert manager")
        .with_crypto_storage(ReachabilityStorage::unreachable());

        let state =
            app_state_with_checks(vec![Arc::new(CertStoreCheck::new(Arc::new(manager)))]).await;
        let resp = call_handler(state, "/health/ready").await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_body(resp).await, "NOT_READY");
    }
}
