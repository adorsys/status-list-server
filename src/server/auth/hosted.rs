//! Composes both trust sources static-first: the operator registry wins, and
//! ids and material are unique across sources (a static kid shadows a hosted kid).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::models::credential::{
    KeyResolveError, PublicJwk, ResolvedKey, canonical_jwk_material,
};
use crate::domain::models::hosted_issuer::{HostedIssuer, HostedIssuerError, HostedIssuerKey};
use crate::domain::ports::{HostedIssuerStore, IssuerKeyResolver};
use crate::server::auth::issuer_registry::{RegistryError, RegistryHandle, ValidatedRegistry};

/// Static-first resolution: a kid owned by both sources resolves to static.
/// Dynamic writes reject registry collisions; a static kid may shadow a hosted kid.
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
                        // A corrupt stored row is a permanent data fault: fail
                        // closed with the uniform 401 rather than a retryable 503.
                        if matches!(error, HostedIssuerError::Corrupt(_)) {
                            tracing::warn!(
                                error = %error,
                                "hosted issuer key row is corrupt; failing closed"
                            );
                            return Err(KeyResolveError::Corrupt);
                        }
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
    // `resolve` is O(1) and complete, catching a kid whose material
    // normalization fails, unlike iterating `all_principal_keys`.
    if snapshot.resolve(&key.kid).is_some() {
        return Err(hosted_conflict(
            "kid is already owned by the static registry",
        ));
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

/// Cross-check only *new* candidate ids/kids/materials against hosted state;
/// collisions fail closed, while a removal applies without touching the store.
pub async fn validate_static_candidate_against_dynamic(
    store: &Arc<dyn HostedIssuerStore>,
    active: &ValidatedRegistry,
    candidate: &ValidatedRegistry,
) -> Result<(), RegistryError> {
    let candidate_keys = candidate.all_principal_keys();
    let active_keys = active.all_principal_keys();
    let active_materials: HashSet<&str> = active_keys
        .iter()
        .map(|(_, _, material)| material.as_str())
        .collect();
    // Only candidate ids that are not already in the active snapshot could
    // shadow a hosted issuer; an id the static source already owns is stable.
    for (principal_id, _, _) in &candidate_keys {
        if active.has_principal_id(principal_id) {
            continue;
        }
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
    }
    // A kid the hosted source already owns is not a startup blocker: the
    // static key wins (shadowed), so only warn about newly introduced kids.
    let active_kids: HashSet<&str> = active_keys.iter().map(|(_, kid, _)| *kid).collect();
    for (_, kid, _) in &candidate_keys {
        if active_kids.contains(kid) {
            continue;
        }
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
    // Reject a candidate key whose material is already registered to a hosted
    // key; the match runs in SQL against the stored material hash.
    for (_, _, material) in &candidate_keys {
        if active_materials.contains(material.as_str()) {
            continue;
        }
        if store
            .key_material_in_use(material)
            .await
            .map_err(dynamic_check_failed)?
        {
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

        async fn key_material_in_use(&self, material: &str) -> Result<bool, HostedIssuerError> {
            let keys = self.keys.lock().await;
            Ok(keys
                .values()
                .any(|key| material_of(&key.jwk).as_deref() == Some(material)))
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
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &registry.snapshot()
            )
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
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &registry.snapshot()
            )
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
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &candidate.snapshot()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn clean_state_passes_candidate_validation() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        assert!(
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &registry.snapshot()
            )
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
        async fn key_material_in_use(&self, _material: &str) -> Result<bool, HostedIssuerError> {
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

    /// A store whose key lookup reports a corrupt stored row.
    #[derive(Debug)]
    struct CorruptHostedStore;

    #[async_trait]
    impl HostedIssuerStore for CorruptHostedStore {
        async fn find_key_by_kid(
            &self,
            _kid: &str,
        ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
            Err(HostedIssuerError::Corrupt("bad state".into()))
        }
        async fn find_issuer(&self, _id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Ok(None)
        }
        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Ok(issuer)
        }
        async fn add_key(&self, _key: HostedIssuerKey) -> Result<(), HostedIssuerError> {
            Ok(())
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(Vec::new())
        }
        async fn key_material_in_use(&self, _material: &str) -> Result<bool, HostedIssuerError> {
            Ok(false)
        }
    }

    /// A corrupt stored row is a permanent data fault: it fails closed as
    /// `Corrupt` (a uniform 401), never as a retryable `BackendUnavailable`.
    #[tokio::test]
    async fn corrupt_stored_row_fails_closed_as_corrupt_not_backend_unavailable() {
        let resolver = CompositeIssuerKeyResolver::new(
            Arc::new(RegistryHandle::empty()),
            Some(Arc::new(CorruptHostedStore) as Arc<dyn HostedIssuerStore>),
        );
        assert!(matches!(
            resolver.resolve("any-kid").await,
            Err(KeyResolveError::Corrupt)
        ));
    }

    /// A removal-only edit must apply even while the hosted store is down:
    /// only *new* entries are cross-checked, so retirement never blocks.
    #[tokio::test]
    async fn removal_only_reload_applies_without_touching_a_down_hosted_store() {
        let store: Arc<dyn HostedIssuerStore> = Arc::new(FailingHostedStore);
        let active = static_registry().snapshot();
        let empty = RegistryHandle::empty().snapshot();
        assert!(
            validate_static_candidate_against_dynamic(&store, &active, &empty)
                .await
                .is_ok(),
            "removing every candidate key must not query the hosted store"
        );
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

    /// A portal-signed management JWT for `issuer_id`, using the private half of
    /// `test_fixtures::TEST_EC_PUBLIC_JWK` (kid `portal-key`).
    #[cfg(all(feature = "memory", feature = "sqlite"))]
    fn portal_token(issuer_id: &str) -> String {
        let private_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("statuslist-management+jwt".to_string());
        header.kid = Some("portal-key".to_string());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": issuer_id, "iat": now, "exp": now + 300 }),
            &jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// No-cache guarantee: a revoked hosted key stops authenticating on the
    /// *next* request, because kid resolution reads the row by primary key with
    /// no cache.
    #[cfg(all(feature = "memory", feature = "sqlite"))]
    #[tokio::test]
    async fn revoking_a_hosted_key_fails_the_next_management_request() {
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
            routing::get,
        };
        use sea_orm::ConnectionTrait;
        use tower::ServiceExt;

        let db = crate::test_utils::sqlite_test_db(None).await;
        let registry = Arc::new(RegistryHandle::empty());
        let store: Arc<dyn HostedIssuerStore> =
            Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(db.clone()));
        let hosted = register_hosted_issuer(&registry, &store, issuer())
            .await
            .unwrap();
        register_hosted_issuer_key(&registry, &store, key("portal-key"))
            .await
            .unwrap();

        let mut state = crate::test_utils::test_app_state(Some(db.clone())).await;
        state.set_issuer_registry(registry.clone());
        state.issuer_key_resolver =
            Arc::new(CompositeIssuerKeyResolver::new(registry, Some(store)));

        let token = portal_token(&hosted.id);
        let app = Router::new()
            .route("/auth-check", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::server::auth::auth,
            ))
            .with_state(state);
        let send = |token: &str| {
            app.clone().oneshot(
                Request::builder()
                    .uri("/auth-check")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
        };

        assert_eq!(
            send(&token).await.unwrap().status(),
            StatusCode::OK,
            "the key authenticates before revocation"
        );

        // Revoke the key row directly; no cache may let it keep authenticating.
        db.execute_unprepared("UPDATE issuer_keys SET state = 'revoked' WHERE kid = 'portal-key'")
            .await
            .unwrap();

        assert_eq!(
            send(&token).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "a revoked hosted key must fail the next request"
        );
    }
}
