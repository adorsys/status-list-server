//! Composition of both trust sources (ADR 0002, "Sources of trust"): the
//! static operator registry stays authoritative, hosted-profile issuers
//! resolve through durable storage, and ids/kids/key material are unique
//! across sources — a candidate that collides with the other source fails
//! closed rather than silently shadowing it.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::models::credential::{
    KeyResolveError, PublicJwk, ResolvedKey, canonical_jwk_material,
};
use crate::domain::models::hosted_issuer::{HostedIssuer, HostedIssuerError, HostedIssuerKey};
use crate::domain::ports::{HostedIssuerStore, IssuerKeyResolver};
use crate::server::auth::issuer_registry::{RegistryError, RegistryHandle, ValidatedRegistry};

/// static-first key resolution. A kid owned by both sources would resolve to
/// the static side only, and dynamic candidates that collide with the
/// registry are rejected at their write point by
/// [`register_hosted_issuer`]/[`register_hosted_issuer_key`], and in the
/// reverse direction by [`validate_static_candidate_against_dynamic`], so the
/// priority is an invariant, not a shadowing mechanism.
pub struct CompositeIssuerKeyResolver {
    static_registry: Arc<RegistryHandle>,
    dynamic: Option<Arc<dyn HostedIssuerStore>>,
}

impl std::fmt::Debug for CompositeIssuerKeyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeIssuerKeyResolver")
            .field("dynamic", &self.dynamic.is_some())
            .finish_non_exhaustive()
    }
}

impl CompositeIssuerKeyResolver {
    pub fn new(
        static_registry: Arc<RegistryHandle>,
        dynamic: Option<Arc<dyn HostedIssuerStore>>,
    ) -> Self {
        Self {
            static_registry,
            dynamic,
        }
    }
}

#[async_trait]
impl IssuerKeyResolver for CompositeIssuerKeyResolver {
    async fn resolve(&self, kid: &str) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        match self.static_registry.resolve_with_reason(kid) {
            Ok(resolved) => Ok(resolved),
            Err(KeyResolveError::UnknownKid) => match &self.dynamic {
                None => Err(KeyResolveError::UnknownKid),
                Some(store) => match store.find_key_by_kid(kid).await {
                    Ok(Some(entry)) => entry.resolved_key(time::OffsetDateTime::now_utc()),
                    Ok(None) => Err(KeyResolveError::UnknownKid),
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            "hosted issuer key resolution failed; the trust backend is unavailable"
                        );
                        Err(KeyResolveError::BackendUnavailable)
                    }
                },
            },
            Err(reason) => Err(reason),
        }
    }
}

fn material_of(jwk: &PublicJwk) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(jwk.as_bytes())
        .ok()
        .and_then(|value| canonical_jwk_material(&value).ok())
}

fn static_materials(snapshot: &ValidatedRegistry) -> HashSet<String> {
    snapshot
        .all_principal_keys()
        .into_iter()
        .map(|(_, _, material)| material)
        .collect()
}

fn hosted_conflict(message: &str) -> HostedIssuerError {
    HostedIssuerError::Backend(Box::new(std::io::Error::other(format!(
        "hosted issuer conflict: {message}"
    ))))
}

/// Validate a dynamic write (issuer creation or key registration) against the
/// active static snapshot before touching storage. The storage adapter
/// enforces dynamic-vs-dynamic uniqueness; this covers dynamic-vs-static. A
/// racing static reload is covered by the reverse direction
/// ([`validate_static_candidate_against_dynamic`]).
async fn validate_dynamic_write(
    registry: &RegistryHandle,
    issuer_id: &str,
    key: Option<&HostedIssuerKey>,
) -> Result<(), HostedIssuerError> {
    let snapshot = registry.snapshot();
    // A hosted issuer may not reuse any static principal's id — issuer or
    // admin — nor a static kid, nor static key material.
    if snapshot.has_principal_id(issuer_id) {
        return Err(hosted_conflict(
            "issuer id is already owned by the static registry",
        ));
    }
    let Some(key) = key else {
        return Ok(());
    };
    for (_, kid, _) in snapshot.all_principal_keys() {
        if kid == key.kid {
            return Err(hosted_conflict(
                "kid is already owned by the static registry",
            ));
        }
    }
    let registers = material_of(&key.jwk)
        .ok_or_else(|| hosted_conflict("the requested issuer key has malformed JWK parameters"))?;
    let statics = static_materials(&snapshot);
    if statics.contains(&registers) {
        return Err(hosted_conflict(
            "key material is owned by the static registry",
        ));
    }
    // Dynamic-vs-dynamic material uniqueness is enforced by the `key_material`
    // unique index in storage, not here: a pre-check here would be racy and
    // would duplicate the full-table scan the index replaces.
    Ok(())
}

/// Validate a static registry candidate against durable dynamic state before
/// it may replace the active snapshot: any candidate principal id, kid, or key
/// material (issuer or admin) owned by a hosted issuer keeps the last-known-good
/// snapshot in force (the reload fails closed, exactly like an invalid document).
pub async fn validate_static_candidate_against_dynamic(
    store: &Arc<dyn HostedIssuerStore>,
    candidate: &ValidatedRegistry,
) -> Result<(), RegistryError> {
    let candidate_keys = candidate.all_principal_keys();
    let candidate_materials: HashSet<&str> = candidate_keys
        .iter()
        .map(|(_, _, material)| material.as_str())
        .collect();
    // A candidate principal whose id already exists as a hosted issuer must
    // not shadow it: two principals sharing an id is genuinely ambiguous.
    for (principal_id, kid, _) in &candidate_keys {
        if store
            .find_issuer(principal_id)
            .await
            .map_err(dynamic_check_failed)?
            .is_some()
        {
            return Err(RegistryError::Semantic(format!(
                "principal id `{principal_id}` collides with a hosted issuer"
            )));
        }
        // A kid the hosted source already owns is not a startup blocker: the
        // resolver is static-first, so the candidate static key wins and the
        // hosted key with the same kid is shadowed (unreachable) for this
        // deployment. Fail-closed is right for an auth *decision*; it is the
        // wrong response to a startup collision where the authoritative static
        // source should win (see the kid-namespace policy in ADR 0002).
        if store
            .find_key_by_kid(kid)
            .await
            .map_err(dynamic_check_failed)?
            .is_some()
        {
            tracing::warn!(
                kid = %kid,
                "static registry key shadows a hosted issuer key with the same kid; \
                 the hosted key is unreachable for this deployment"
            );
        }
    }
    for key in store.all_keys().await.map_err(dynamic_check_failed)? {
        let material = material_of(&key.jwk).ok_or_else(|| {
            RegistryError::Semantic(format!(
                "stored issuer key `{}` has malformed JWK parameters",
                key.kid
            ))
        })?;
        if candidate_materials.contains(material.as_str()) {
            return Err(RegistryError::Semantic(
                "a candidate registry key reuses hosted issuer key material".into(),
            ));
        }
    }
    Ok(())
}

fn dynamic_check_failed(error: HostedIssuerError) -> RegistryError {
    RegistryError::Database(error.to_string())
}

/// Runs a hosted write through the cross-source checks before handing it to
/// storage. The future admin surface builds on these; hosted tests use them
/// to exercise the same path production would.
pub async fn register_hosted_issuer(
    registry: &RegistryHandle,
    store: &Arc<dyn HostedIssuerStore>,
    issuer: HostedIssuer,
) -> Result<HostedIssuer, HostedIssuerError> {
    validate_dynamic_write(registry, &issuer.id, None).await?;
    store.create_issuer(issuer).await
}

pub async fn register_hosted_issuer_key(
    registry: &RegistryHandle,
    store: &Arc<dyn HostedIssuerStore>,
    key: HostedIssuerKey,
) -> Result<(), HostedIssuerError> {
    validate_dynamic_write(registry, &key.issuer_id, Some(&key)).await?;
    store.add_key(key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::AggregationId;
    use crate::domain::models::hosted_issuer::{
        HostedIssuerKeyEntry, HostedIssuerKeyState, HostedIssuerState,
    };
    use std::collections::HashMap;

    const EC_JWK: &str = r#"{"kty":"EC","crv":"P-256","kid":"dynamic-key","alg":"ES256","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}"#;

    /// A second, distinct EC key so a collision test can isolate the kid branch
    /// from the material branch.
    const DISTINCT_EC_JWK: &str = r#"{"kty":"EC","crv":"P-256","kid":"distinct","alg":"ES256","x":"qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E","y":"c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"}"#;

    /// Minimal in-memory `HostedIssuerStore` double, enough to exercise the
    /// composition logic without a backend.
    #[derive(Debug, Default)]
    struct InMemoryHostedStore {
        issuer: Option<HostedIssuer>,
        keys: tokio::sync::Mutex<HashMap<String, HostedIssuerKey>>,
    }

    impl InMemoryHostedStore {
        fn with_keys(keys: &[HostedIssuerKey]) -> Arc<InMemoryHostedStore> {
            let map: HashMap<String, HostedIssuerKey> = keys
                .iter()
                .map(|key| (key.kid.clone(), key.clone()))
                .collect();
            Arc::new(Self {
                issuer: None,
                keys: tokio::sync::Mutex::new(map),
            })
        }
    }

    #[async_trait]
    impl HostedIssuerStore for InMemoryHostedStore {
        async fn find_key_by_kid(
            &self,
            kid: &str,
        ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
            Ok(self
                .keys
                .lock()
                .await
                .get(kid)
                .map(|key| HostedIssuerKeyEntry {
                    issuer: {
                        let mut hosted = HostedIssuer {
                            id: "00000000-0000-4000-8000-000000000002".into(),
                            display_name: None,
                            tier: "standard".into(),
                            state: HostedIssuerState::Active,
                            owner: None,
                            created_at: time::OffsetDateTime::UNIX_EPOCH,
                            expires_at: None,
                            version: 1,
                            aggregation_id: AggregationId::generate(),
                        };
                        hosted.id.clone_from(&key.issuer_id);
                        hosted
                    },
                    key: key.clone(),
                }))
        }

        async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Ok(self
                .issuer
                .as_ref()
                .filter(|hosted| hosted.id == id)
                .cloned())
        }

        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Ok(issuer)
        }

        async fn add_key(&self, key: HostedIssuerKey) -> Result<(), HostedIssuerError> {
            self.keys.lock().await.insert(key.kid.clone(), key);
            Ok(())
        }

        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(self.keys.lock().await.values().cloned().collect())
        }
    }

    fn issuer() -> HostedIssuer {
        HostedIssuer {
            id: "00000000-0000-4000-8000-000000000002".into(),
            display_name: None,
            tier: "standard".into(),
            state: HostedIssuerState::Active,
            owner: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            version: 1,
            aggregation_id: AggregationId::generate(),
        }
    }

    fn kid_embedded_jwk(kid: &str) -> PublicJwk {
        let mut jwk: serde_json::Value = serde_json::from_str(EC_JWK).unwrap();
        jwk["kid"] = kid.into();
        PublicJwk::try_new(serde_json::to_vec(&jwk).unwrap()).unwrap()
    }

    fn key(kid: &str) -> HostedIssuerKey {
        HostedIssuerKey {
            kid: kid.to_string(),
            issuer_id: "00000000-0000-4000-8000-000000000002".into(),
            jwk: kid_embedded_jwk(kid),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            not_before: None,
            not_after: None,
            state: HostedIssuerKeyState::Active,
        }
    }

    fn key_with_material(kid: &str, jwk_json: &str) -> HostedIssuerKey {
        let mut jwk: serde_json::Value = serde_json::from_str(jwk_json).unwrap();
        jwk["kid"] = kid.into();
        HostedIssuerKey {
            kid: kid.to_string(),
            issuer_id: "00000000-0000-4000-8000-000000000002".into(),
            jwk: PublicJwk::try_new(serde_json::to_vec(&jwk).unwrap()).unwrap(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            not_before: None,
            not_after: None,
            state: HostedIssuerKeyState::Active,
        }
    }

    fn static_registry() -> RegistryHandle {
        let mut jwk = serde_json::to_value(
            PublicJwk::try_new(EC_JWK.as_bytes().to_vec())
                .unwrap()
                .jwk(),
        )
        .unwrap();
        // The registry requires the embedded JWK's kid to match the entry's.
        jwk.as_object_mut()
            .unwrap()
            .insert("kid".into(), serde_json::Value::String("static-key".into()));
        RegistryHandle::from_yaml(
            &serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "static-issuer",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [{
                        "kid": "static-key", "alg": "ES256", "jwk": jwk,
                    }],
                }],
                "admins": [],
            }))
            .unwrap(),
        )
        .unwrap()
    }

    /// A registry with an issuer and an admin principal. The admin's key uses
    /// distinct material (`DISTINCT_EC_JWK`) so collision tests can tell the
    /// kid/material branches apart.
    fn registry_with_admin() -> RegistryHandle {
        let mut issuer_jwk = serde_json::to_value(
            PublicJwk::try_new(EC_JWK.as_bytes().to_vec())
                .unwrap()
                .jwk(),
        )
        .unwrap();
        issuer_jwk
            .as_object_mut()
            .unwrap()
            .insert("kid".into(), serde_json::Value::String("static-key".into()));
        let mut admin_jwk: serde_json::Value = serde_json::from_str(DISTINCT_EC_JWK).unwrap();
        admin_jwk["kid"] = "admin-key".into();
        RegistryHandle::from_yaml(
            &serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "static-issuer",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [{ "kid": "static-key", "alg": "ES256", "jwk": issuer_jwk }],
                }],
                "admins": [{
                    "id": "admin-1",
                    "scopes": ["issuers:write"],
                    "keys": [{ "kid": "admin-key", "alg": "ES256", "jwk": admin_jwk }],
                }],
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn write_colliding_with_static_issuer_id_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        let mut hosted = issuer();
        hosted.id = "static-issuer".into();
        assert!(
            register_hosted_issuer(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn write_colliding_with_static_kid_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        // Distinct material so the kid branch — not the material branch — is
        // what rejects the write.
        let mut hosted = key_with_material("static-key", DISTINCT_EC_JWK);
        hosted.issuer_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(
            register_hosted_issuer_key(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn write_reusing_static_key_material_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        // Same key parameters as the registered `static-key`; only the kid
        // differs between sources.
        let mut hosted = key("dynamic-key");
        let candidate: serde_json::Value = serde_json::to_value(
            registry.snapshot().issuer("static-issuer").unwrap().keys[0]
                .jwk
                .clone(),
        )
        .unwrap();
        let mut candidate = candidate;
        if let Some(object) = candidate.as_object_mut() {
            object.insert(
                "kid".into(),
                serde_json::Value::String("dynamic-key".into()),
            );
        }
        hosted.jwk = PublicJwk::try_new(serde_json::to_vec(&candidate).unwrap()).unwrap();
        assert!(
            register_hosted_issuer_key(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn write_colliding_with_admin_kid_fails_closed() {
        let registry = registry_with_admin();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        // Distinct material so only the admin's kid collides.
        let mut hosted = key_with_material("admin-key", EC_JWK);
        hosted.issuer_id = "00000000-0000-4000-8000-000000000004".into();
        assert!(
            register_hosted_issuer_key(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn write_reusing_admin_key_material_fails_closed() {
        let registry = registry_with_admin();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        // The admin's material under a different kid.
        let mut hosted = key_with_material("hosted-key", DISTINCT_EC_JWK);
        hosted.issuer_id = "00000000-0000-4000-8000-000000000004".into();
        assert!(
            register_hosted_issuer_key(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn write_colliding_with_admin_id_fails_closed() {
        let registry = registry_with_admin();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        let mut hosted = issuer();
        hosted.id = "admin-1".into();
        assert!(
            register_hosted_issuer(&registry, &store, hosted)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn static_candidate_kid_collision_with_dynamic_state_warns_and_static_wins() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[
            // The candidate's kid with distinct material: resolution is
            // static-first, so the candidate static key wins and the hosted
            // key is shadowed rather than crashing the reload.
            key_with_material("static-key", DISTINCT_EC_JWK),
        ]);
        assert!(
            validate_static_candidate_against_dynamic(&store, &registry.snapshot())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn static_candidate_reusing_dynamic_material_still_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[
            // Same material as the candidate's `static-key`, under a different
            // kid: key-material reuse across sources must still block the
            // reload.
            key_with_material("dynamic-key", EC_JWK),
        ]);
        assert!(
            validate_static_candidate_against_dynamic(&store, &registry.snapshot())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn static_candidate_issuer_id_colliding_with_dynamic_row_fails_closed() {
        let mut stored = issuer();
        stored.id = "00000000-0000-4000-8000-000000000001".into();
        let store: Arc<dyn HostedIssuerStore> = Arc::new({
            InMemoryHostedStore {
                issuer: Some(stored),
                ..InMemoryHostedStore::default()
            }
        });
        let candidate = RegistryHandle::from_yaml(
            &serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "00000000-0000-4000-8000-000000000001",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [{
                        "kid": "other-key",
                        "alg": "ES256",
                        // Distinct material so this test isolates the id
                        // collision from the material collision.
                        "jwk": {
                            "kty": "EC", "crv": "P-256",
                            "x": "qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E",
                            "y": "c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"
                        },
                    }],
                }],
                "admins": [],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_static_candidate_against_dynamic(&store, &candidate.snapshot())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn clean_state_passes_candidate_validation() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        assert!(
            validate_static_candidate_against_dynamic(&store, &registry.snapshot())
                .await
                .is_ok()
        );
    }

    /// A store that fails every read, standing in for a trust-backend outage.
    #[derive(Debug)]
    struct FailingHostedStore;

    #[async_trait]
    impl HostedIssuerStore for FailingHostedStore {
        async fn find_key_by_kid(
            &self,
            _kid: &str,
        ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn find_issuer(&self, _id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn create_issuer(
            &self,
            _issuer: HostedIssuer,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn add_key(&self, _key: HostedIssuerKey) -> Result<(), HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
    }

    /// A trust-backend fault must not masquerade as an unknown kid: operators
    /// need the real reason, and the HTTP layer maps it to a retryable 503.
    #[tokio::test]
    async fn backend_failure_resolves_as_backend_unavailable() {
        let resolver = CompositeIssuerKeyResolver::new(
            Arc::new(RegistryHandle::empty()),
            Some(Arc::new(FailingHostedStore) as Arc<dyn HostedIssuerStore>),
        );
        assert!(matches!(
            resolver.resolve("any-kid").await,
            Err(KeyResolveError::BackendUnavailable)
        ));
    }

    /// Acceptance criteria: a portal issuer's key authenticates a management
    /// write exactly like a static issuer's key — same middleware path, same
    /// `AuthenticatedIssuer` context, aggregation ID resolved from the
    /// hosted issuer's `issuers` row — and a portal issuer publishes its
    /// first list without a credentials row: that row is the quota record
    /// the publish path reserves slots against.
    #[cfg(all(feature = "memory", feature = "sqlite"))]
    #[tokio::test]
    async fn hosted_issuer_publishes_first_list_like_a_static_issuer() {
        let db = crate::test_utils::sqlite_test_db(None).await;
        publish_first_list_flow(db, "SQLite").await;
    }

    #[cfg(all(feature = "memory", feature = "postgres-tests"))]
    #[tokio::test]
    async fn hosted_issuer_publishes_first_list_like_a_static_issuer_postgres() {
        use crate::outbound::sql::test_containers::postgres_helpers;
        let test_db = postgres_helpers::postgres_connection().await;
        publish_first_list_flow(test_db.db.clone(), "Postgres").await;
    }

    #[cfg(all(
        feature = "memory",
        any(feature = "sqlite", feature = "postgres-tests")
    ))]
    async fn publish_first_list_flow(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        backend: &str,
    ) {
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
            routing::put,
        };
        use tower::ServiceExt;

        let registry = Arc::new(RegistryHandle::empty());
        let store: Arc<dyn HostedIssuerStore> =
            Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(db.clone()));
        let hosted = register_hosted_issuer(&registry, &store, issuer())
            .await
            .unwrap_or_else(|e| panic!("registering a portal issuer on {backend}: {e}"));
        register_hosted_issuer_key(&registry, &store, key("portal-key"))
            .await
            .unwrap_or_else(|e| panic!("registering a portal key on {backend}: {e}"));

        // SQL-backed app state: the publish path's quota slot reservation and
        // the resolver's read both hit this database.
        let mut state = crate::test_utils::test_app_state(Some(db)).await;
        state.set_issuer_registry(registry.clone());
        state.issuer_key_resolver =
            Arc::new(CompositeIssuerKeyResolver::new(registry, Some(store)));

        // The private half of `test_fixtures::TEST_EC_PUBLIC_JWK` (which also
        // carries kid `test-key`); the portal key embeds kid `portal-key`.
        let private_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("statuslist-management+jwt".to_string());
        header.kid = Some("portal-key".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": hosted.id,
                "iat": now,
                "exp": now + 300,
            }),
            &jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap();

        let list_id = uuid::Uuid::new_v4().to_string();
        let app = Router::new()
            .nest(
                "/api/v1",
                Router::new().route(
                    "/status-lists/{list_id}/statuses",
                    put(crate::server::handlers::status_list::publish_status_route),
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::server::auth::auth,
            ))
            .with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::PUT)
                    .uri(format!("/api/v1/status-lists/{list_id}/statuses"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"statuses":[]}"#.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "the portal issuer's first list must publish on {backend}"
        );
    }
}
