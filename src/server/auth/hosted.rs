//! Composes both trust sources static-first: the operator registry is
//! authoritative, and ids, kids and key material are unique across sources.
//! Collisions fail closed: a hosted write that collides with the registry is
//! rejected, a registry candidate that collides with hosted state is rejected
//! (the last-known-good snapshot stays in force), and the resolver rechecks
//! ownership on every hosted hit so a registration/reload race can never leave
//! one key trusted under two identities.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::models::credential::{
    KeyResolveError, PublicJwk, ResolvedKey, canonical_jwk_material,
};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerKey, HostedIssuerKeyEntry, HostedIssuerKeyState,
};
use crate::domain::ports::{HostedIssuerStore, IssuerKeyResolver};
use crate::server::auth::issuer_registry::{RegistryError, RegistryHandle, ValidatedRegistry};

/// Static-first resolution. A hosted key is served only while the static
/// registry owns neither its issuer id nor its key material; otherwise the
/// request fails closed with `SourceConflict` (a uniform 401 at the edge).
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

    /// Why a hosted entry must not be served right now, if the *current*
    /// static snapshot owns something it claims.
    fn static_conflict(&self, entry: &HostedIssuerKeyEntry) -> Option<&'static str> {
        let snapshot = self.static_registry.snapshot();
        if snapshot.has_principal_id(&entry.issuer.id) {
            return Some("issuer id is owned by the static registry");
        }
        match entry.key.jwk.normalized_material() {
            Ok(material) if snapshot.has_key_material(&material) => {
                Some("key material is owned by the static registry")
            }
            Ok(_) => None,
            Err(_) => Some("stored key material cannot be normalized"),
        }
    }
}

#[async_trait]
impl IssuerKeyResolver for CompositeIssuerKeyResolver {
    async fn resolve(&self, kid: &str) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        match self.static_registry.resolve_with_reason(kid) {
            Ok(resolved) => Ok(resolved),
            Err(KeyResolveError::UnknownKid) => {
                match &self.dynamic {
                    None => Err(KeyResolveError::UnknownKid),
                    Some(store) => match store.find_key_by_kid(kid).await {
                        Ok(Some(entry)) => {
                            // Reject a reserved key first: the kid is known but
                            // never authenticates, and checking before
                            // static_conflict avoids a spurious error-level
                            // collision log for adopted legacy issuers whose old
                            // reserved row is still present.
                            if entry.key.state == HostedIssuerKeyState::Reserved {
                                tracing::debug!(
                                    kid = %entry.key.kid,
                                    issuer = %entry.issuer.id,
                                    "hosted key is reserved and does not authenticate; \
                                     adopt it into the registry to enable it"
                                );
                                return Err(KeyResolveError::Reserved);
                            }
                            if let Some(reason) = self.static_conflict(&entry) {
                                tracing::error!(
                                    kid = %kid,
                                    issuer = %entry.issuer.id,
                                    reason,
                                    "hosted key collides with the static registry; failing closed"
                                );
                                return Err(KeyResolveError::SourceConflict);
                            }
                            entry.resolved_key(time::OffsetDateTime::now_utc())
                        }
                        Ok(None) => Err(KeyResolveError::UnknownKid),
                        Err(error) => {
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
                }
            }
            Err(reason) => Err(reason),
        }
    }
}

fn material_of(jwk: &PublicJwk) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(jwk.as_bytes())
        .ok()
        .and_then(|value| canonical_jwk_material(&value).ok())
}

/// Validate a dynamic write (issuer creation or key registration) against the
/// active static snapshot before touching storage. The storage adapter
/// enforces dynamic-vs-dynamic uniqueness; this covers dynamic-vs-static. A
/// racing static reload is covered by the resolver's per-request recheck
/// (`static_conflict`).
async fn validate_dynamic_write(
    registry: &RegistryHandle,
    issuer_id: &str,
    key: Option<&HostedIssuerKey>,
) -> Result<(), HostedIssuerError> {
    let snapshot = registry.snapshot();
    // A hosted issuer may not reuse a static principal's id (issuer or admin),
    // a static kid, or static key material. Conflicts are typed so callers can
    // map them to 4xx rather than retrying a 5xx.
    if snapshot.has_principal_id(issuer_id) {
        return Err(HostedIssuerError::AlreadyExists);
    }
    let Some(key) = key else {
        return Ok(());
    };
    // `resolve` is O(1) and complete, catching a kid whose material
    // normalization fails, unlike iterating `all_principal_keys`.
    if snapshot.resolve(&key.kid).is_some() || snapshot.has_revoked_kid(&key.kid) {
        return Err(HostedIssuerError::AlreadyExists);
    }
    let registers = material_of(&key.jwk).ok_or_else(|| {
        HostedIssuerError::InvalidPublicJwk(
            "the requested issuer key has malformed JWK parameters".into(),
        )
    })?;
    if snapshot.has_key_material(&registers) {
        return Err(HostedIssuerError::KeyMaterialReused);
    }
    // Dynamic-vs-dynamic material uniqueness is enforced by the `key_material`
    // unique index in storage, not here: a pre-check here would be racy and
    // would duplicate the full-table scan the index replaces.
    Ok(())
}

/// Cross-check only *new* candidate ids and kids, and materials not already
/// admitted, against hosted state.
pub async fn validate_static_candidate_against_dynamic(
    store: &Arc<dyn HostedIssuerStore>,
    active: &ValidatedRegistry,
    candidate: &ValidatedRegistry,
) -> Result<(), RegistryError> {
    let candidate_keys = candidate.all_principal_keys();
    let active_keys = active.all_principal_keys();
    let active_material_by_kid: HashMap<&str, &str> = active_keys
        .iter()
        .map(|(_, kid, m)| (*kid, m.as_str()))
        .collect();
    let mut checked_ids: HashSet<&str> = HashSet::new();

    for (principal_id, kid, material) in &candidate_keys {
        if !active.has_principal_id(principal_id)
            && checked_ids.insert(principal_id)
            && store
                .find_issuer(principal_id)
                .await
                .map_err(dynamic_check_failed)?
                .is_some()
        {
            return Err(RegistryError::Semantic(format!(
                "principal id `{principal_id}` collides with a hosted issuer"
            )));
        }
        // A candidate entry whose kid and material are both unchanged from the
        // active snapshot was already admitted; no hosted cross-check is needed.
        if active_material_by_kid.get(kid) == Some(&material.as_str()) {
            continue;
        }
        // A new kid (absent from the active snapshot) must not collide with a
        // hosted kid, unless it is the same identity adopted into the registry.
        if !active_material_by_kid.contains_key(kid) {
            match store
                .find_key_by_kid(kid)
                .await
                .map_err(dynamic_check_failed)?
            {
                Some(entry)
                    if entry.issuer.id == *principal_id
                        && entry.key.jwk.normalized_material().ok().as_deref()
                            == Some(material.as_str()) =>
                {
                    continue; // the same identity, adopted into the registry
                }
                Some(_) => {
                    return Err(RegistryError::Semantic(format!(
                        "candidate key `{kid}` collides with a hosted issuer key with the same kid; \
                         kids are unique across trust sources, so the candidate is rejected"
                    )));
                }
                None => {}
            }
        }
        // New or changed material: always re-check it against the hosted store,
        // even when the kid was already admitted with different material.
        // A Reserved row of the same principal is a carry-over awaiting adoption
        // and must not block the registry from adopting its own material under a
        // new kid (e.g. the RFC 7638 thumbprint written by the issuer export).
        if let Some(blocker) = store
            .find_key_by_material(material)
            .await
            .map_err(dynamic_check_failed)?
        {
            let is_own_reserved = blocker.issuer_id == *principal_id
                && blocker.state == HostedIssuerKeyState::Reserved;
            if !is_own_reserved {
                return Err(RegistryError::Semantic(
                    "a candidate registry key reuses hosted issuer key material".into(),
                ));
            }
        }
    }
    Ok(())
}

fn dynamic_check_failed(error: HostedIssuerError) -> RegistryError {
    RegistryError::Database(error.to_string())
}

/// Runs a hosted write through the cross-source checks before handing it to
/// storage. Crate-private: the public API builds on
/// [`HostedIssuerService`](crate::server::auth::hosted_service::HostedIssuerService)
/// (which assigns identifiers) rather than accepting whole entities; hosted
/// tests use this to exercise the same path production would.
///
/// The registry write lock serializes this with a reload in the same process
/// only. If a reload on another pod races it, `static_conflict` fails the
/// hosted key closed rather than trusting it twice.
pub(crate) async fn register_hosted_issuer(
    registry: &RegistryHandle,
    store: &Arc<dyn HostedIssuerStore>,
    issuer: HostedIssuer,
    actor: &str,
) -> Result<HostedIssuer, HostedIssuerError> {
    let _guard = registry.write_lock().await;
    validate_dynamic_write(registry, &issuer.id, None).await?;
    store.create_issuer(issuer, actor).await
}

pub(crate) async fn register_hosted_issuer_key(
    registry: &RegistryHandle,
    store: &Arc<dyn HostedIssuerStore>,
    key: HostedIssuerKey,
    actor: &str,
) -> Result<(), HostedIssuerError> {
    let _guard = registry.write_lock().await;
    validate_dynamic_write(registry, &key.issuer_id, Some(&key)).await?;
    store.add_key(key, actor).await
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
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Ok(issuer)
        }

        async fn add_key(
            &self,
            key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            self.keys.lock().await.insert(key.kid.clone(), key);
            Ok(())
        }

        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(self.keys.lock().await.values().cloned().collect())
        }

        async fn find_key_by_material(
            &self,
            material: &str,
        ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
            let keys = self.keys.lock().await;
            Ok(keys
                .values()
                .find(|key| material_of(&key.jwk).as_deref() == Some(material))
                .cloned())
        }

        async fn find_issuer_ids(
            &self,
            ids: &[String],
        ) -> Result<HashSet<String>, HostedIssuerError> {
            let stored = self.issuer.as_ref().map(|hosted| hosted.id.clone());
            Ok(ids
                .iter()
                .filter(|id| stored.as_deref() == Some(id.as_str()))
                .cloned()
                .collect())
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
            matches!(
                register_hosted_issuer(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::AlreadyExists)
            ),
            "an id collision with the static registry must be a typed AlreadyExists, not Backend"
        );
    }

    #[tokio::test]
    async fn write_colliding_with_static_kid_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        // Distinct material so the kid branch, not the material branch, rejects
        // the write.
        let mut hosted = key_with_material("static-key", DISTINCT_EC_JWK);
        hosted.issuer_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(
            matches!(
                register_hosted_issuer_key(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::AlreadyExists)
            ),
            "a kid collision with the static registry must be a typed AlreadyExists, not Backend"
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
            matches!(
                register_hosted_issuer_key(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::KeyMaterialReused)
            ),
            "material reuse against the static registry must be typed KeyMaterialReused, not Backend"
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
            matches!(
                register_hosted_issuer_key(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::AlreadyExists)
            ),
            "an admin kid collision must be a typed AlreadyExists, not Backend"
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
            matches!(
                register_hosted_issuer_key(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::KeyMaterialReused)
            ),
            "admin material reuse must be typed KeyMaterialReused, not Backend"
        );
    }

    #[tokio::test]
    async fn write_colliding_with_admin_id_fails_closed() {
        let registry = registry_with_admin();
        let store: Arc<dyn HostedIssuerStore> = Arc::new(InMemoryHostedStore::default());
        let mut hosted = issuer();
        hosted.id = "admin-1".into();
        assert!(
            matches!(
                register_hosted_issuer(&registry, &store, hosted, "portal-operator").await,
                Err(HostedIssuerError::AlreadyExists)
            ),
            "an admin id collision must be a typed AlreadyExists, not Backend"
        );
    }

    #[tokio::test]
    async fn static_candidate_kid_collision_with_dynamic_state_fails_closed() {
        let registry = static_registry();
        // Same kid, distinct material, different issuer: the material check
        // passes, so only the kid rule can reject this.
        let store: Arc<dyn HostedIssuerStore> =
            InMemoryHostedStore::with_keys(&[key_with_material("static-key", DISTINCT_EC_JWK)]);
        let error = validate_static_candidate_against_dynamic(
            &store,
            &RegistryHandle::empty().snapshot(),
            &registry.snapshot(),
        )
        .await
        .expect_err("a kid owned by a hosted key must reject the candidate");
        assert!(error.to_string().contains("static-key"), "{error}");
    }

    #[tokio::test]
    async fn static_candidate_matching_a_hosted_identity_is_adopted_not_rejected() {
        let registry = static_registry();
        let mut carried = key_with_material("static-key", EC_JWK);
        carried.issuer_id = "static-issuer".into();
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[carried]);
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

    /// A carry-over Reserved row uses the legacy kid from the credential row.
    /// The issuer export writes the RFC 7638 thumbprint as the kid, so the
    /// kid-level adoption check cannot match. The material check must
    /// recognise that the blocker is a Reserved row of the same principal and
    /// allow the adoption rather than failing with "reuses hosted issuer key
    /// material".
    #[tokio::test]
    async fn reserved_row_of_same_principal_does_not_block_adoption_under_thumbprint_kid() {
        let registry = static_registry(); // principal "static-issuer", kid "static-key"

        // Simulate the carry-over: the reserved row keeps the *legacy* kid
        // but holds the same key material as the candidate.
        let mut reserved = key_with_material("legacy-1", EC_JWK);
        reserved.issuer_id = "static-issuer".into();
        reserved.state = HostedIssuerKeyState::Reserved;
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[reserved]);

        // The candidate uses "static-key" as the kid; find_key_by_kid won't
        // find it in the hosted store, so the material check fires.  The
        // Reserved row belongs to the same principal, so it must be allowed.
        assert!(
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &registry.snapshot()
            )
            .await
            .is_ok(),
            "a Reserved carry-over row of the same principal must not block adoption under a different kid"
        );
    }

    /// An Active row of the *same* principal under a different kid must still
    /// block: the issuer has an active hosted key that wasn't exported into the
    /// registry.
    #[tokio::test]
    async fn active_material_of_same_principal_under_different_kid_is_still_rejected() {
        let registry = static_registry();
        let mut active = key_with_material("other-kid", EC_JWK);
        active.issuer_id = "static-issuer".into();
        active.state = HostedIssuerKeyState::Active;
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[active]);
        assert!(
            validate_static_candidate_against_dynamic(
                &store,
                &RegistryHandle::empty().snapshot(),
                &registry.snapshot()
            )
            .await
            .is_err(),
            "an Active hosted row with the same material but a different kid must still block the candidate"
        );
    }

    /// An operator who removed a key from the registry must not see it come
    /// back through a carried-over hosted row for the same issuer.
    #[tokio::test]
    async fn hosted_key_for_a_statically_owned_issuer_never_resolves() {
        let registry = Arc::new(static_registry());
        let mut stale = key_with_material("rotated-out", DISTINCT_EC_JWK);
        stale.issuer_id = "static-issuer".into();
        let store: Arc<dyn HostedIssuerStore> = InMemoryHostedStore::with_keys(&[stale]);
        let resolver = CompositeIssuerKeyResolver::new(registry, Some(store));
        assert!(matches!(
            resolver.resolve("rotated-out").await,
            Err(KeyResolveError::SourceConflict)
        ));
    }

    /// Wraps a store and parks inside `add_key` so a reload can run to
    /// completion while the hosted write is uncommitted.
    struct GatedStore {
        inner: Arc<InMemoryHostedStore>,
        reached: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl HostedIssuerStore for GatedStore {
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
            kid: &str,
        ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
            self.inner.find_key_by_kid(kid).await
        }
        async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            self.inner.find_issuer(id).await
        }
        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
            actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            self.inner.create_issuer(issuer, actor).await
        }
        async fn add_key(
            &self,
            key: HostedIssuerKey,
            actor: &str,
        ) -> Result<(), HostedIssuerError> {
            self.reached.notify_one();
            self.release.notified().await;
            self.inner.add_key(key, actor).await
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            self.inner.all_keys().await
        }
        async fn find_key_by_material(
            &self,
            material: &str,
        ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
            self.inner.find_key_by_material(material).await
        }
        async fn find_issuer_ids(
            &self,
            ids: &[String],
        ) -> Result<HashSet<String>, HostedIssuerError> {
            self.inner.find_issuer_ids(ids).await
        }
    }

    /// Forces the interleaving where registration validates against
    /// the empty snapshot and parks inside `add_key` while still holding the
    /// registry write lock.
    #[tokio::test]
    async fn registration_racing_a_reload_commits_at_most_one_source() {
        let registry = Arc::new(RegistryHandle::empty());
        let gated = Arc::new(GatedStore {
            inner: InMemoryHostedStore::with_keys(&[]),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let store: Arc<dyn HostedIssuerStore> = gated.clone();

        let registration = tokio::spawn({
            let (registry, store) = (registry.clone(), store.clone());
            async move {
                register_hosted_issuer_key(
                    &registry,
                    &store,
                    key_with_material("hosted-kid", EC_JWK),
                    "portal-operator",
                )
                .await
            }
        });
        gated.reached.notified().await; // validated against the empty snapshot

        // The reload's critical section is serialized behind the write lock:
        // it cannot install the static snapshot until the write commits.
        let candidate = (*static_registry().snapshot()).clone(); // static-key, same material
        let reload = tokio::spawn({
            let (registry, store) = (registry.clone(), store.clone());
            async move {
                let _guard = registry.write_lock().await;
                let active = registry.snapshot();
                validate_static_candidate_against_dynamic(&store, &active, &candidate).await
            }
        });

        // Let the write commit, then the reload runs and must be rejected.
        gated.release.notify_one();
        registration
            .await
            .unwrap()
            .expect("the hosted write commits");
        assert!(
            reload.await.unwrap().is_err(),
            "a static candidate reusing committed hosted material must be rejected"
        );

        // The conflicting static snapshot was never installed, so the hosted
        // key resolves on its own and no cross-source duplicate is persisted.
        assert!(
            !registry.snapshot().has_key_material(
                &canonical_jwk_material(
                    &serde_json::from_str::<serde_json::Value>(EC_JWK).unwrap()
                )
                .unwrap()
            ),
            "the static snapshot must not own the hosted key's material"
        );
        let resolver = CompositeIssuerKeyResolver::new(registry, Some(store));
        assert!(resolver.resolve("hosted-kid").await.is_ok());
        assert!(matches!(
            resolver.resolve("static-key").await,
            Err(KeyResolveError::UnknownKid)
        ));
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

    /// A candidate may keep a kid across reloads only if its material is
    /// unchanged: swapping the JWK under a known kid to material a hosted key
    /// holds must still be rejected (the old `continue` skipped this check).
    #[tokio::test]
    async fn static_candidate_swapping_material_under_a_known_kid_is_rejected() {
        let mut jwk_a: serde_json::Value = serde_json::from_str(EC_JWK).unwrap();
        jwk_a["kid"] = "k".into();
        let mut jwk_b: serde_json::Value = serde_json::from_str(DISTINCT_EC_JWK).unwrap();
        jwk_b["kid"] = "k".into();
        let active = RegistryHandle::from_yaml(
            &serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "static-issuer",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [{ "kid": "k", "alg": "ES256", "jwk": jwk_a }],
                }],
                "admins": [],
            }))
            .unwrap(),
        )
        .unwrap();
        // A hosted key already holds material B (under a different kid).
        let store: Arc<dyn HostedIssuerStore> =
            InMemoryHostedStore::with_keys(&[key_with_material("hosted-kid", DISTINCT_EC_JWK)]);
        let candidate = RegistryHandle::from_yaml(
            &serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "static-issuer",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [{ "kid": "k", "alg": "ES256", "jwk": jwk_b }],
                }],
                "admins": [],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_static_candidate_against_dynamic(
                &store,
                &active.snapshot(),
                &candidate.snapshot()
            )
            .await
            .is_err(),
            "a reload that swaps a known kid's material to hosted-held material must be rejected"
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
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn add_key(
            &self,
            _key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn find_key_by_material(
            &self,
            _material: &str,
        ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
            Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "backend down",
            ))))
        }
        async fn find_issuer_ids(
            &self,
            _ids: &[String],
        ) -> Result<HashSet<String>, HostedIssuerError> {
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
            Err(HostedIssuerError::Corrupt("bad state".into()))
        }
        async fn find_issuer(&self, _id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Ok(None)
        }
        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            Ok(issuer)
        }
        async fn add_key(
            &self,
            _key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            Ok(())
        }
        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(Vec::new())
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

    /// A hosted issuer's key authenticates a management write like a static key:
    /// same middleware path and `AuthenticatedIssuer` context, with the aggregation
    /// ID taken from its `issuers` row. Its first publish needs no credentials row,
    /// because the `issuers` row is the quota record.
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

    #[cfg(all(feature = "memory", feature = "mysql"))]
    #[tokio::test]
    async fn hosted_issuer_publishes_first_list_like_a_static_issuer_mysql() {
        use crate::outbound::sql::test_containers::mysql_helpers;
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        publish_first_list_flow(test_db.connection().await, "MySQL").await;
    }

    /// The public half of a second EC pair, distinct from `key()`'s, so the
    /// revocation of one key can be observed while the issuer stays writable
    /// through the other.
    #[cfg(all(
        feature = "memory",
        any(feature = "sqlite", feature = "postgres-tests", feature = "mysql")
    ))]
    const SECOND_EC_JWK: &str = r#"{
        "kty":"EC", "crv": "P-256", "kid": "ignored", "alg": "ES256",
        "x": "qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E",
        "y": "c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"
    }"#;

    /// The private half of [`SECOND_EC_JWK`].
    #[cfg(all(
        feature = "memory",
        any(feature = "sqlite", feature = "postgres-tests", feature = "mysql")
    ))]
    const SECOND_EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB\nAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA\n///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV\nAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg\n9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A\nAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgyO8dO/IXvyo2\nloV5QPB42Gv31v5U5pik40FfQ12VVzWhRANCAASozvoFuoPcmZaeJPgC5JgzkrDE\nLlYA1w9cGkJRB8B/UXP3TuiR9gairPTOlLAzTEO0bGDIMKjjeU4tfYCm/Jy5\n-----END PRIVATE KEY-----";

    #[cfg(all(
        feature = "memory",
        any(feature = "sqlite", feature = "postgres-tests", feature = "mysql")
    ))]
    async fn publish_first_list_flow(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        backend: &str,
    ) {
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
            routing::{get, put},
        };
        use tower::ServiceExt;

        let registry = Arc::new(RegistryHandle::empty());
        let store: Arc<dyn HostedIssuerStore> =
            Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(db.clone()));
        let hosted = register_hosted_issuer(&registry, &store, issuer(), "portal-operator")
            .await
            .unwrap_or_else(|e| panic!("registering a portal issuer on {backend}: {e}"));
        register_hosted_issuer_key(&registry, &store, key("portal-key"), "portal-operator")
            .await
            .unwrap_or_else(|e| panic!("registering a portal key on {backend}: {e}"));

        // SQL-backed app state: the publish path's quota slot reservation and
        // the resolver's read both hit this database.
        let mut state = crate::test_utils::test_app_state(Some(db.clone())).await;
        state.set_issuer_registry(registry.clone());
        state.issuer_key_resolver = Arc::new(CompositeIssuerKeyResolver::new(
            registry,
            Some(store.clone()),
        ));
        let mut other_state = crate::test_utils::test_app_state(Some(db.clone())).await;
        let other_registry = Arc::new(RegistryHandle::empty());
        other_state.set_issuer_registry(other_registry.clone());
        other_state.issuer_key_resolver = Arc::new(CompositeIssuerKeyResolver::new(
            other_registry,
            Some(Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(
                db.clone(),
            ))),
        ));

        // The private half of `test_fixtures::TEST_EC_PUBLIC_JWK` (which also
        // carries kid `test-key`); the hosted key embeds kid `portal-key`.
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
        let router = |state: crate::server::AppState| {
            let management = Router::new()
                .route(
                    "/api/v1/status-lists/{list_id}/statuses",
                    put(crate::server::handlers::status_list::publish_status_route),
                )
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::server::auth::auth,
                ));
            let public = Router::new().route(
                "/api/v1/status-lists/{list_id}",
                get(crate::server::handlers::get_status_list),
            );
            Router::new()
                .merge(management)
                .merge(public)
                .with_state(state)
        };
        let app = router(state);
        let other = router(other_state);
        let response = app
            .clone()
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
        async fn write(app: Router, token: &str) -> StatusCode {
            use tower::ServiceExt;
            app.oneshot(
                Request::builder()
                    .method(axum::http::Method::PUT)
                    .uri(format!(
                        "/api/v1/status-lists/{}/statuses",
                        uuid::Uuid::new_v4()
                    ))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"statuses":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
        async fn public_read(app: &Router, list_id: &str) -> StatusCode {
            use tower::ServiceExt;
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/status-lists/{list_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        // The second replica must prove it can publish at all before any
        // lifecycle change, or its later 401 would show nothing.
        assert_eq!(
            write(other.clone(), &token).await,
            StatusCode::CREATED,
            "the second replica must publish on {backend} before suspension"
        );

        use crate::domain::ports::HostedIssuerLifecycleStore;
        let lifecycle = crate::outbound::sql::SqlHostedIssuerStore::new(db.clone());
        lifecycle
            .set_issuer_state(
                &hosted.id,
                HostedIssuerState::Suspended,
                hosted.version,
                "portal-operator",
            )
            .await
            .unwrap();
        for replica in [app.clone(), other.clone()] {
            assert_eq!(write(replica, &token).await, StatusCode::UNAUTHORIZED);
        }
        for replica in [app.clone(), other.clone()] {
            assert_eq!(public_read(&replica, &list_id).await, StatusCode::OK);
        }
        lifecycle
            .set_issuer_state(
                &hosted.id,
                HostedIssuerState::Active,
                hosted.version + 1,
                "portal-operator",
            )
            .await
            .unwrap();
        // Writes must work again after reactivation: the expiry check below
        // would otherwise pass even if reactivation had silently failed.
        for replica in [app.clone(), other.clone()] {
            assert_eq!(
                write(replica, &token).await,
                StatusCode::CREATED,
                "writes must recover after reactivation on {backend}"
            );
        }
        // Revocation blocks the next write on every replica, not just key
        // resolution.
        lifecycle
            .revoke_key(&hosted.id, "portal-key", "portal-operator")
            .await
            .unwrap();
        for replica in [app.clone(), other.clone()] {
            assert_eq!(
                write(replica, &token).await,
                StatusCode::UNAUTHORIZED,
                "a revoked key must block the next write on {backend}"
            );
        }
        // A second key keeps the issuer writable; expiry then blocks it while
        // the published lists stay publicly readable.
        register_hosted_issuer_key(
            &Arc::new(RegistryHandle::empty()),
            &store,
            key_with_material("portal-key-2", SECOND_EC_JWK),
            "portal-operator",
        )
        .await
        .unwrap_or_else(|e| panic!("registering the second portal key on {backend}: {e}"));
        let mut second_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        second_header.typ = Some("statuslist-management+jwt".to_string());
        second_header.kid = Some("portal-key-2".to_string());
        let second_token = jsonwebtoken::encode(
            &second_header,
            &serde_json::json!({
                "iss": hosted.id,
                "iat": now,
                "exp": now + 300,
            }),
            &jsonwebtoken::EncodingKey::from_ec_pem(SECOND_EC_PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        for replica in [app.clone(), other.clone()] {
            assert_eq!(
                write(replica.clone(), &second_token).await,
                StatusCode::CREATED,
                "the second key must publish on {backend}"
            );
        }
        use crate::outbound::sql::issuers;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};
        issuers::Entity::update_many()
            .col_expr(
                issuers::Column::ExpiresAt,
                Expr::value(time::OffsetDateTime::now_utc().unix_timestamp() - 1),
            )
            .filter(issuers::Column::Issuer.eq(&hosted.id))
            .exec(db.as_ref())
            .await
            .unwrap();
        for replica in [app.clone(), other.clone()] {
            assert_eq!(
                write(replica.clone(), &second_token).await,
                StatusCode::UNAUTHORIZED,
                "an expired issuer must block writes on {backend}"
            );
            assert_eq!(
                public_read(&replica, &list_id).await,
                StatusCode::OK,
                "an expired issuer's lists must stay publicly readable on {backend}"
            );
        }
    }

    /// A hosted-signed management JWT for `issuer_id`, using the private half of
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
        let hosted = register_hosted_issuer(&registry, &store, issuer(), "portal-operator")
            .await
            .unwrap();
        register_hosted_issuer_key(&registry, &store, key("portal-key"), "portal-operator")
            .await
            .unwrap();

        let mut state = crate::test_utils::test_app_state(Some(db.clone())).await;
        state.set_issuer_registry(registry.clone());
        state.issuer_key_resolver = Arc::new(CompositeIssuerKeyResolver::new(
            registry,
            Some(store.clone()),
        ));

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
