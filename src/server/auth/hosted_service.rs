//! The public API for creating hosted-profile issuers and keys. Callers
//! supply operator metadata only; the server assigns `id`, `aggregation_id`,
//! `created_at`, `version`, and the key `kid` (ADR 0002, Identifiers). The
//! entity-taking registration functions are crate-private.

use std::sync::Arc;
use time::OffsetDateTime;

use crate::domain::models::credential::{AggregationId, PublicJwk};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerKey, HostedIssuerKeyState, HostedIssuerState,
    NewHostedIssuer, NewHostedIssuerKey,
};
use crate::domain::ports::{HostedIssuerLifecycleStore, HostedIssuerStore};
use crate::server::auth::hosted::{
    register_hosted_issuer, register_hosted_issuer_key, register_hosted_issuer_key_if_version,
};
use crate::server::auth::issuer_registry::RegistryHandle;

/// Assigns server-side identifiers for a hosted write and commits it through
/// the cross-source checks. The clock and id source are injectable so tests can
/// stay deterministic.
pub struct HostedIssuerService {
    store: Arc<dyn HostedIssuerStore>,
    clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    new_id: Arc<dyn Fn() -> uuid::Uuid + Send + Sync>,
}

impl HostedIssuerService {
    pub fn new(store: Arc<dyn HostedIssuerStore>) -> Self {
        Self::with_sources(
            store,
            Arc::new(OffsetDateTime::now_utc),
            Arc::new(uuid::Uuid::new_v4),
        )
    }

    pub fn with_sources(
        store: Arc<dyn HostedIssuerStore>,
        clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
        new_id: Arc<dyn Fn() -> uuid::Uuid + Send + Sync>,
    ) -> Self {
        Self {
            store,
            clock,
            new_id,
        }
    }

    /// Create a hosted issuer, assigning a UUIDv4 id, an immutable aggregation
    /// id, `created_at`, and `version`. Returns `HostedIssuerError::InvalidExpiry`
    /// if `expires_at` is already in the past so a caller cannot create an
    /// issuer that is immediately unusable.
    pub async fn create_issuer(
        &self,
        registry: &RegistryHandle,
        input: NewHostedIssuer,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        let now = (self.clock)();
        if input.expires_at <= now {
            return Err(HostedIssuerError::InvalidExpiry(
                "expires_at must be in the future".into(),
            ));
        }
        let issuer = HostedIssuer {
            id: (self.new_id)().to_string(),
            display_name: input.display_name,
            tier: input.tier,
            state: HostedIssuerState::Active,
            owner: input.owner,
            created_at: now,
            expires_at: Some(input.expires_at),
            version: 1,
            aggregation_id: AggregationId((self.new_id)()),
        };
        register_hosted_issuer(registry, &self.store, issuer, actor).await
    }

    /// Register a signing key, assigning its kid and `created_at`. The returned
    /// key carries the assigned kid, which the caller needs to report back.
    pub async fn register_key(
        &self,
        registry: &RegistryHandle,
        input: NewHostedIssuerKey,
        actor: &str,
    ) -> Result<HostedIssuerKey, HostedIssuerError> {
        let kid = key_thumbprint(&input.jwk)?;
        let mut map = input.jwk;
        map.insert("kid".into(), serde_json::Value::String(kid.clone()));
        let bytes = serde_json::to_vec(&map)
            .map_err(|e| HostedIssuerError::InvalidPublicJwk(e.to_string()))?;
        let jwk = PublicJwk::try_new(bytes)
            .map_err(|e| HostedIssuerError::InvalidPublicJwk(e.to_string()))?;
        let key = HostedIssuerKey {
            kid,
            issuer_id: input.issuer_id,
            jwk,
            created_at: (self.clock)(),
            not_before: input.not_before,
            not_after: input.not_after,
            state: HostedIssuerKeyState::Active,
        };
        register_hosted_issuer_key(registry, &self.store, key.clone(), actor).await?;
        Ok(key)
    }

    /// Register a key only if the issuer has not changed since the admin
    /// client read its ETag.
    pub async fn register_key_if_version(
        &self,
        registry: &RegistryHandle,
        input: NewHostedIssuerKey,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuerKey, HostedIssuerError> {
        let kid = key_thumbprint(&input.jwk)?;
        let mut map = input.jwk;
        map.insert("kid".into(), serde_json::Value::String(kid.clone()));
        let bytes = serde_json::to_vec(&map)
            .map_err(|e| HostedIssuerError::InvalidPublicJwk(e.to_string()))?;
        let jwk = PublicJwk::try_new(bytes)
            .map_err(|e| HostedIssuerError::InvalidPublicJwk(e.to_string()))?;
        let key = HostedIssuerKey {
            kid,
            issuer_id: input.issuer_id,
            jwk,
            created_at: (self.clock)(),
            not_before: input.not_before,
            not_after: input.not_after,
            state: HostedIssuerKeyState::Active,
        };
        register_hosted_issuer_key_if_version(
            registry,
            &self.store,
            key.clone(),
            expected_version,
            actor,
        )
        .await?;
        Ok(key)
    }
}

fn key_thumbprint(
    jwk: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, HostedIssuerError> {
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(serde_json::Value::Object(jwk.clone()))
            .map_err(|error| HostedIssuerError::InvalidPublicJwk(error.to_string()))?;
    jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .map_err(|error| HostedIssuerError::InvalidPublicJwk(error.to_string()))
}

/// Applies operator lifecycle commands to durable state. The decision rules
/// (no reactivation after expiry, the no-op case) live here behind an
/// injectable clock, so they are testable without a database and a second
/// backend does not have to copy them; the store commits each transition
/// together with its audit event.
pub struct HostedIssuerLifecycleService {
    store: Arc<dyn HostedIssuerLifecycleStore>,
    clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

impl std::fmt::Debug for HostedIssuerLifecycleService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedIssuerLifecycleService")
            .finish_non_exhaustive()
    }
}

impl HostedIssuerLifecycleService {
    pub fn new(store: Arc<dyn HostedIssuerLifecycleStore>) -> Self {
        Self::with_clock(store, Arc::new(OffsetDateTime::now_utc))
    }

    pub fn with_clock(
        store: Arc<dyn HostedIssuerLifecycleStore>,
        clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    ) -> Self {
        Self { store, clock }
    }

    pub async fn get_issuer(&self, issuer_id: &str) -> Result<HostedIssuer, HostedIssuerError> {
        self.store.get_issuer(issuer_id).await
    }

    pub async fn set_issuer_state(
        &self,
        issuer_id: &str,
        state: HostedIssuerState,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        let current = self.store.get_issuer(issuer_id).await?;
        if state == HostedIssuerState::Active
            && current
                .expires_at
                .is_some_and(|expiry| expiry <= (self.clock)())
        {
            return Err(HostedIssuerError::InvalidExpiry(
                "an expired issuer cannot be reactivated".into(),
            ));
        }
        // Re-applying the stored state is a no-op: report it unchanged
        // without a version bump or an audit event.
        if current.state == state {
            return Ok(current);
        }
        self.store
            .set_issuer_state(issuer_id, state, expected_version, actor)
            .await
    }

    pub async fn revoke_key(
        &self,
        issuer_id: &str,
        kid: &str,
        actor: &str,
    ) -> Result<HostedIssuerKey, HostedIssuerError> {
        self.store.revoke_key(issuer_id, kid, actor).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::hosted_issuer::HostedIssuerKeyEntry;
    use crate::server::auth::issuer_registry::RegistryHandle;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingStore {
        issuer: Mutex<Option<HostedIssuer>>,
        key: Mutex<Option<HostedIssuerKey>>,
    }

    #[async_trait::async_trait]
    impl HostedIssuerStore for RecordingStore {
        async fn list_issuers_after(
            &self,
            _after: Option<&str>,
            _limit: usize,
            _filters: &crate::domain::models::hosted_issuer::HostedIssuerFilter,
            _now: time::OffsetDateTime,
        ) -> Result<Vec<HostedIssuer>, HostedIssuerError> {
            unreachable!("this authentication fixture does not serve admin reads")
        }
        async fn issuer_keys(
            &self,
            _issuer_id: &str,
        ) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            unreachable!("this authentication fixture does not serve admin reads")
        }

        async fn find_key_by_kid(
            &self,
            _kid: &str,
        ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
            Ok(self
                .key
                .lock()
                .unwrap()
                .clone()
                .map(|key| HostedIssuerKeyEntry {
                    issuer: self.issuer.lock().unwrap().clone().unwrap(),
                    key,
                }))
        }
        async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Ok(self.issuer.lock().unwrap().clone().filter(|h| h.id == id))
        }
        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            *self.issuer.lock().unwrap() = Some(issuer.clone());
            Ok(issuer)
        }
        async fn add_key(
            &self,
            key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            *self.key.lock().unwrap() = Some(key);
            Ok(())
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(self.key.lock().unwrap().clone().into_iter().collect())
        }
        async fn find_key_by_material(
            &self,
            _material: &str,
        ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
            Ok(None)
        }
        async fn find_issuer_ids(
            &self,
            _ids: &[String],
        ) -> Result<HashSet<String>, HostedIssuerError> {
            Ok(HashSet::new())
        }
    }

    fn deterministic_service(
        store: Arc<dyn HostedIssuerStore>,
    ) -> (HostedIssuerService, Arc<Mutex<u64>>) {
        let counter = Arc::new(Mutex::new(0u64));
        let ids = counter.clone();
        let new_id: Arc<dyn Fn() -> uuid::Uuid + Send + Sync> = Arc::new(move || {
            let mut n = ids.lock().unwrap();
            *n += 1;
            uuid::Uuid::from_u64_pair(0, *n)
        });
        let clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync> =
            Arc::new(|| OffsetDateTime::UNIX_EPOCH);
        (
            HostedIssuerService::with_sources(store, clock, new_id),
            counter,
        )
    }

    #[tokio::test]
    async fn create_issuer_assigns_server_identifiers_and_keeps_expiry() {
        let store = Arc::new(RecordingStore::default()) as Arc<dyn HostedIssuerStore>;
        let (service, counter) = deterministic_service(store.clone());
        let registry = RegistryHandle::empty();
        let expires = OffsetDateTime::UNIX_EPOCH + time::Duration::days(30);

        let created = service
            .create_issuer(
                &registry,
                NewHostedIssuer {
                    display_name: Some("Acme".into()),
                    tier: "standard".into(),
                    owner: Some("ops".into()),
                    expires_at: expires,
                },
                "portal-operator",
            )
            .await
            .unwrap();

        assert_eq!(created.id, uuid::Uuid::from_u64_pair(0, 1).to_string());
        assert_eq!(
            created.aggregation_id,
            AggregationId(uuid::Uuid::from_u64_pair(0, 2))
        );
        assert_eq!(created.created_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(created.version, 1);
        assert_eq!(created.state, HostedIssuerState::Active);
        assert_eq!(created.expires_at, Some(expires));
        // The caller must not choose the id: the store holds what the service assigned.
        let stored = store.find_issuer(&created.id).await.unwrap().unwrap();
        assert_eq!(stored.id, created.id);
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn register_key_assigns_kid_and_created_at() {
        let store = Arc::new(RecordingStore::default()) as Arc<dyn HostedIssuerStore>;
        let (service, _counter) = deterministic_service(store.clone());
        let registry = RegistryHandle::empty();
        // The store must resolve the owning issuer for the cross-source path to
        // find nothing; the empty registry means no static conflict.
        let issuer = service
            .create_issuer(
                &registry,
                NewHostedIssuer {
                    display_name: None,
                    tier: "standard".into(),
                    owner: None,
                    expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
                },
                "portal-operator",
            )
            .await
            .unwrap();

        let key = service
            .register_key(
                &registry,
                NewHostedIssuerKey {
                    issuer_id: issuer.id.clone(),
                    jwk: serde_json::json!({
                        "kty": "EC", "crv": "P-256", "alg": "ES256",
                        "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                        "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M",
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                    not_before: None,
                    not_after: None,
                },
                "portal-operator",
            )
            .await
            .unwrap();

        // The kid is server-assigned (third id), not caller-chosen, and the JWK
        // embeds the same kid so storage's kid/embedding invariant holds.
        assert_eq!(key.kid, uuid::Uuid::from_u64_pair(0, 3).to_string());
        assert_eq!(key.jwk.key_id(), key.kid);
        assert_eq!(key.created_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(key.issuer_id, issuer.id);
        let stored = store.all_keys().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].kid, key.kid);
    }

    #[tokio::test]
    async fn create_issuer_rejects_already_expired_expiry() {
        let store = Arc::new(RecordingStore::default()) as Arc<dyn HostedIssuerStore>;
        let (service, _counter) = deterministic_service(store.clone());
        let registry = RegistryHandle::empty();

        // The deterministic clock is pinned at UNIX_EPOCH; any expires_at at or
        // before that instant must be rejected so an issuer cannot be created
        // already expired.
        for expires in [
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(1),
        ] {
            assert!(
                matches!(
                    service
                        .create_issuer(
                            &registry,
                            NewHostedIssuer {
                                display_name: None,
                                tier: "standard".into(),
                                owner: None,
                                expires_at: expires,
                            },
                            "portal-operator",
                        )
                        .await,
                    Err(HostedIssuerError::InvalidExpiry(_))
                ),
                "expires_at={expires:?} must be rejected as already in the past"
            );
        }
    }

    /// A lifecycle store that records guarded writes without a database, so
    /// the service rules are testable on their own.
    struct RecordingLifecycleStore {
        issuer: Mutex<HostedIssuer>,
        writes: Mutex<Vec<(HostedIssuerState, u64)>>,
    }

    #[async_trait::async_trait]
    impl HostedIssuerLifecycleStore for RecordingLifecycleStore {
        async fn get_issuer(&self, _id: &str) -> Result<HostedIssuer, HostedIssuerError> {
            Ok(self.issuer.lock().unwrap().clone())
        }

        async fn set_issuer_state(
            &self,
            _id: &str,
            state: HostedIssuerState,
            expected_version: u64,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            self.writes
                .lock()
                .unwrap()
                .push((state.clone(), expected_version));
            let mut issuer = self.issuer.lock().unwrap();
            if issuer.version != expected_version {
                return Err(HostedIssuerError::VersionMismatch);
            }
            issuer.state = state;
            issuer.version += 1;
            Ok(issuer.clone())
        }

        async fn revoke_key(
            &self,
            _issuer_id: &str,
            _kid: &str,
            _actor: &str,
        ) -> Result<HostedIssuerKey, HostedIssuerError> {
            unreachable!("these rule tests do not revoke")
        }
    }

    fn lifecycle_fixture(
        state: HostedIssuerState,
        expires_at: Option<OffsetDateTime>,
    ) -> HostedIssuer {
        HostedIssuer {
            id: "00000000-0000-4000-8000-000000000001".into(),
            display_name: None,
            tier: "standard".into(),
            state,
            owner: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            expires_at,
            version: 1,
            aggregation_id: AggregationId::generate(),
        }
    }

    fn lifecycle_service_with_clock(
        store: Arc<RecordingLifecycleStore>,
        now: OffsetDateTime,
    ) -> HostedIssuerLifecycleService {
        HostedIssuerLifecycleService::with_clock(store, Arc::new(move || now))
    }

    #[tokio::test]
    async fn reactivating_an_expired_issuer_is_rejected_before_any_write() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let store = Arc::new(RecordingLifecycleStore {
            issuer: Mutex::new(lifecycle_fixture(
                HostedIssuerState::Suspended,
                Some(now - time::Duration::days(1)),
            )),
            writes: Mutex::new(Vec::new()),
        });
        let service = lifecycle_service_with_clock(store.clone(), now);

        let result = service
            .set_issuer_state(
                "00000000-0000-4000-8000-000000000001",
                HostedIssuerState::Active,
                1,
                "portal-admin",
            )
            .await;
        assert!(matches!(result, Err(HostedIssuerError::InvalidExpiry(_))));
        assert!(
            store.writes.lock().unwrap().is_empty(),
            "the rejected reactivation must not reach the store"
        );
    }

    #[tokio::test]
    async fn re_applying_the_stored_state_is_a_noop_without_a_write() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let store = Arc::new(RecordingLifecycleStore {
            issuer: Mutex::new(lifecycle_fixture(
                HostedIssuerState::Suspended,
                Some(now + time::Duration::days(1)),
            )),
            writes: Mutex::new(Vec::new()),
        });
        let service = lifecycle_service_with_clock(store.clone(), now);

        let issuer = service
            .set_issuer_state(
                "00000000-0000-4000-8000-000000000001",
                HostedIssuerState::Suspended,
                1,
                "portal-admin",
            )
            .await
            .unwrap();
        assert_eq!(issuer.state, HostedIssuerState::Suspended);
        assert_eq!(
            issuer.version, 1,
            "a no-op must not bump the version or write an audit event"
        );
        assert!(store.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_real_change_reaches_the_store_with_the_read_version() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let store = Arc::new(RecordingLifecycleStore {
            issuer: Mutex::new(lifecycle_fixture(
                HostedIssuerState::Active,
                Some(now + time::Duration::days(1)),
            )),
            writes: Mutex::new(Vec::new()),
        });
        let service = lifecycle_service_with_clock(store.clone(), now);

        let issuer = service
            .set_issuer_state(
                "00000000-0000-4000-8000-000000000001",
                HostedIssuerState::Suspended,
                1,
                "portal-admin",
            )
            .await
            .unwrap();
        assert_eq!(issuer.state, HostedIssuerState::Suspended);
        assert_eq!(issuer.version, 2);
        assert_eq!(
            *store.writes.lock().unwrap(),
            vec![(HostedIssuerState::Suspended, 1)]
        );
    }
}
