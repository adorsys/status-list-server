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
                            "hosted issuer key resolution failed; failing closed"
                        );
                        Err(KeyResolveError::UnknownKid)
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
        .issuers()
        .iter()
        .flat_map(|issuer| issuer.keys.iter())
        .filter_map(|key| {
            let material = canonical_jwk_material(&key.jwk);
            material.ok()
        })
        .collect()
}

fn dynamic_materials(keys: &[HostedIssuerKey]) -> Result<HashSet<String>, HostedIssuerError> {
    keys.iter()
        .map(|key| {
            material_of(&key.jwk).ok_or_else(|| {
                hosted_conflict(&format!(
                    "stored issuer key `{}` has malformed JWK parameters",
                    key.kid
                ))
            })
        })
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
    store: &Arc<dyn HostedIssuerStore>,
    issuer_id: &str,
    key: Option<&HostedIssuerKey>,
) -> Result<(), HostedIssuerError> {
    let snapshot = registry.snapshot();
    if snapshot.issuer(issuer_id).is_some() {
        return Err(hosted_conflict(
            "issuer id is already owned by the static registry",
        ));
    }
    let Some(key) = key else {
        return Ok(());
    };
    for issuer in snapshot.issuers() {
        for static_key in &issuer.keys {
            if static_key.kid == key.kid {
                return Err(hosted_conflict(
                    "kid is already owned by the static registry",
                ));
            }
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
    let dynamics = dynamic_materials(&store.all_keys().await?)?;
    if dynamics.contains(&registers) {
        return Err(hosted_conflict(
            "key material is already used by another issuer",
        ));
    }
    Ok(())
}

/// Validate a static registry candidate against durable dynamic state before
/// it may replace the active snapshot: any candidate issuer id, kid, or key
/// material owned by a hosted issuer keeps the last-known-good snapshot in
/// force (the reload fails closed, exactly like an invalid document).
pub async fn validate_static_candidate_against_dynamic(
    store: &Arc<dyn HostedIssuerStore>,
    candidate: &ValidatedRegistry,
) -> Result<(), RegistryError> {
    let mut candidate_materials: HashSet<String> = HashSet::new();
    for issuer in candidate.issuers() {
        if store
            .find_issuer(&issuer.id)
            .await
            .map_err(dynamic_check_failed)?
            .is_some()
        {
            return Err(RegistryError::Semantic(format!(
                "issuer id `{}` collides with a hosted issuer",
                issuer.id
            )));
        }
        for key in &issuer.keys {
            if store
                .find_key_by_kid(&key.kid)
                .await
                .map_err(dynamic_check_failed)?
                .is_some()
            {
                return Err(RegistryError::Semantic(format!(
                    "kid `{}` collides with a hosted issuer key",
                    key.kid
                )));
            }
            let material = canonical_jwk_material(&key.jwk).map_err(RegistryError::Semantic)?;
            candidate_materials.insert(material);
        }
    }
    for key in store.all_keys().await.map_err(dynamic_check_failed)? {
        let material = material_of(&key.jwk).ok_or_else(|| {
            RegistryError::Semantic(format!(
                "stored issuer key `{}` has malformed JWK parameters",
                key.kid
            ))
        })?;
        if candidate_materials.contains(&material) {
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
    validate_dynamic_write(registry, store, &issuer.id, None).await?;
    store.create_issuer(issuer).await
}

pub async fn register_hosted_issuer_key(
    registry: &RegistryHandle,
    store: &Arc<dyn HostedIssuerStore>,
    key: HostedIssuerKey,
) -> Result<(), HostedIssuerError> {
    validate_dynamic_write(registry, store, &key.issuer_id, Some(&key)).await?;
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

    #[tokio::test]
    async fn write_colliding_with_static_issuer_id_fails_closed() {
        let registry = RegistryHandle::empty();
        assert!(registry.snapshot().issuer("static-issuer").is_none());
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
        let mut hosted = key("static-key");
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
    async fn static_candidate_colliding_with_dynamic_state_fails_closed() {
        let registry = static_registry();
        let store: Arc<dyn HostedIssuerStore> =
            InMemoryHostedStore::with_keys(&[key("dynamic-key")]);
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

    /// Acceptance criterion: a portal issuer's key authenticates a management
    /// write exactly like a static issuer's key — same middleware path, same
    /// `AuthenticatedIssuer` context, aggregation ID resolved from the
    /// hosted issuer's immutable mapping.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn hosted_issuer_key_authenticates_like_a_static_key() {
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
            routing::get,
        };
        use tower::ServiceExt;

        let registry = Arc::new(RegistryHandle::empty());
        let db = crate::test_utils::sqlite_test_db(None).await;
        let store: Arc<dyn HostedIssuerStore> =
            Arc::new(crate::outbound::sql::SqlHostedIssuerStore::new(db.clone()));
        let mut hosted = issuer();
        hosted.id = "00000000-0000-4000-8000-000000000002".into();
        let hosted = register_hosted_issuer(&registry, &store, hosted)
            .await
            .unwrap();
        register_hosted_issuer_key(&registry, &store, key("portal-key"))
            .await
            .unwrap();

        let mut state = crate::test_utils::test_app_state(None).await;
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

        let app = Router::new()
            .route("/test", get(|| async { "Ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::server::auth::auth,
            ))
            .with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
