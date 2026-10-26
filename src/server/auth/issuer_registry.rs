//! Operator-managed issuer trust registry.
//!
//! This module loads, validates, and resolves the trusted keys used by
//! authentication.

use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::models::credential::{
    AggregationId, KeyResolveError, Principal, PublicJwk, ResolvedKey,
};
use crate::domain::ports::{IssuerDirectory, IssuerKeyResolver};

const REGISTRY_SCHEMA: &str = include_str!("../../../docs/schemas/issuers.v1.schema.json");

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("failed to read issuer registry `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse issuer registry YAML: {0}")]
    Parse(#[from] serde_saphyr::Error),
    #[error("issuer registry schema validation failed: {0}")]
    Schema(String),
    #[error("issuer registry semantic validation failed: {0}")]
    Semantic(String),
    #[error("issuer registry database check failed: {0}")]
    Database(String),
    #[error("issuer registry schema is invalid: {0}")]
    SchemaDefinition(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerRegistry {
    pub version: u8,
    #[serde(default)]
    pub issuers: Vec<IssuerEntry>,
    #[serde(default)]
    pub admins: Vec<AdminEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerEntry {
    pub id: String,
    pub aggregation_id: uuid::Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub disabled: bool,
    pub keys: Vec<Arc<RegistryKey>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminEntry {
    pub id: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
    pub keys: Vec<Arc<RegistryKey>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegistryKey {
    pub kid: String,
    pub alg: String,
    pub jwk: Value,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ValidatedRegistry {
    registry: IssuerRegistry,
    fingerprint: String,
    keys: HashMap<String, Arc<ResolvedKey>>,
    issuer_aggregations: HashMap<String, AggregationId>,
    aggregation_issuers: HashMap<AggregationId, String>,
}

/// Atomically replaceable, last-known-good registry used by request handlers.
#[derive(Debug)]
pub struct RegistryHandle {
    path: PathBuf,
    active: ArcSwap<ValidatedRegistry>,
    aggregation_history: Mutex<AggregationHistory>,
    reload_failures: AtomicU64,
}

#[derive(Debug, Default)]
struct AggregationHistory {
    by_issuer: HashMap<String, AggregationId>,
    by_id: HashMap<AggregationId, String>,
}

/// File-backed implementation name used in the issue and operational docs.
pub type StaticFileRegistry = RegistryHandle;

impl RegistryHandle {
    pub fn from_yaml(content: &str) -> Result<Self, RegistryError> {
        Ok(Self::new(
            PathBuf::from("<memory>"),
            IssuerRegistry::from_yaml(content)?,
        ))
    }

    pub fn empty() -> Self {
        Self::new(
            PathBuf::from("<empty>"),
            IssuerRegistry::from_yaml("version: 1\nissuers: []\nadmins: []\n")
                .expect("empty registry is valid"),
        )
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        let registry = IssuerRegistry::from_file(&path)?;
        Ok(Self::new(path, registry))
    }

    fn new(path: PathBuf, registry: ValidatedRegistry) -> Self {
        Self {
            path,
            aggregation_history: Mutex::new(AggregationHistory {
                by_issuer: registry.issuer_aggregations.clone(),
                by_id: registry.aggregation_issuers.clone(),
            }),
            reload_failures: AtomicU64::new(0),
            active: ArcSwap::from_pointee(registry),
        }
    }

    pub fn snapshot(&self) -> Arc<ValidatedRegistry> {
        self.active.load_full()
    }

    pub fn reload_failure_count(&self) -> u64 {
        self.reload_failures.load(Ordering::Relaxed)
    }

    pub fn record_reload_failure(&self) {
        self.reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resolve_with_reason(&self, kid: &str) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        let now = time::OffsetDateTime::now_utc();
        self.snapshot().resolve_with_reason_at(kid, now)
    }

    pub fn resolve(&self, kid: &str) -> Option<Arc<ResolvedKey>> {
        self.resolve_with_reason(kid).ok()
    }

    pub fn reload(&self) -> Result<(), RegistryError> {
        let registry = IssuerRegistry::from_file(&self.path)?;
        self.replace(registry)
    }

    /// Apply a registry only after external consistency checks have succeeded.
    pub fn replace(&self, registry: ValidatedRegistry) -> Result<(), RegistryError> {
        let registry = Arc::new(registry);
        self.validate_candidate(&registry)?;
        let mut history = self
            .aggregation_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history
            .by_issuer
            .extend(registry.issuer_aggregations.clone());
        history.by_id.extend(registry.aggregation_issuers.clone());
        self.active.store(registry);
        Ok(())
    }

    /// Check immutable aggregation history before making external adoption writes.
    pub fn validate_candidate(&self, registry: &ValidatedRegistry) -> Result<(), RegistryError> {
        let history = self
            .aggregation_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (issuer, next) in &registry.issuer_aggregations {
            if history
                .by_issuer
                .get(issuer)
                .is_some_and(|current| current != next)
            {
                return Err(RegistryError::Semantic(format!(
                    "aggregation_id for issuer `{issuer}` is immutable"
                )));
            }
        }
        for (aggregation_id, issuer) in &registry.aggregation_issuers {
            if history
                .by_id
                .get(aggregation_id)
                .is_some_and(|current| current != issuer)
            {
                return Err(RegistryError::Semantic(format!(
                    "issuer for aggregation_id `{aggregation_id}` is immutable"
                )));
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait::async_trait]
impl IssuerKeyResolver for RegistryHandle {
    async fn resolve(&self, kid: &str) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        self.resolve_with_reason(kid)
    }
}

impl IssuerDirectory for RegistryHandle {
    fn issuer_aggregation_id(&self, issuer: &str) -> Option<AggregationId> {
        self.snapshot().issuer_aggregation_id(issuer)
    }

    fn issuer_by_aggregation_id(&self, aggregation_id: AggregationId) -> Option<String> {
        self.snapshot()
            .issuer_by_aggregation_id(aggregation_id)
            .map(str::to_owned)
    }
}

impl IssuerRegistry {
    pub fn from_file(path: impl AsRef<Path>) -> Result<ValidatedRegistry, RegistryError> {
        let content =
            std::fs::read_to_string(path.as_ref()).map_err(|source| RegistryError::Read {
                path: path.as_ref().to_path_buf(),
                source,
            })?;
        Self::from_yaml(&content)
    }

    pub fn from_yaml(content: &str) -> Result<ValidatedRegistry, RegistryError> {
        let json: Value = serde_saphyr::from_str(content)?;
        validate_schema(&json)?;
        let registry: Self =
            serde_json::from_value(json).map_err(|err| RegistryError::Schema(err.to_string()))?;
        validate_semantics(&registry)?;
        let now = time::OffsetDateTime::now_utc();
        for issuer in &registry.issuers {
            if !issuer.keys.iter().any(|key| key_is_active(key, now)) {
                tracing::warn!(issuer = %issuer.id, "issuer has no currently valid signing key");
            }
        }

        let mut keys = HashMap::new();
        let mut issuer_aggregations = HashMap::new();
        let mut aggregation_issuers = HashMap::new();
        for issuer in &registry.issuers {
            let aggregation_id = AggregationId(issuer.aggregation_id);
            issuer_aggregations.insert(issuer.id.clone(), aggregation_id);
            aggregation_issuers.insert(aggregation_id, issuer.id.clone());
            for key in &issuer.keys {
                keys.insert(
                    key.kid.clone(),
                    Arc::new(ResolvedKey {
                        principal: Principal::Issuer {
                            id: issuer.id.clone(),
                            aggregation_id,
                        },
                        public_key: Arc::new(validated_public_key(key)?),
                        enabled: !issuer.disabled,
                        not_before: parsed_window(key.not_before.as_deref()),
                        not_after: parsed_window(key.not_after.as_deref()),
                    }),
                );
            }
        }
        for admin in &registry.admins {
            for key in &admin.keys {
                keys.insert(
                    key.kid.clone(),
                    Arc::new(ResolvedKey {
                        principal: Principal::Admin {
                            id: admin.id.clone(),
                        },
                        public_key: Arc::new(validated_public_key(key)?),
                        enabled: !admin.disabled,
                        not_before: parsed_window(key.not_before.as_deref()),
                        not_after: parsed_window(key.not_after.as_deref()),
                    }),
                );
            }
        }

        Ok(ValidatedRegistry {
            registry,
            fingerprint: hex::encode(Sha256::digest(content.as_bytes())),
            keys,
            issuer_aggregations,
            aggregation_issuers,
        })
    }
}

impl ValidatedRegistry {
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn resolve(&self, kid: &str) -> Option<Arc<ResolvedKey>> {
        self.keys.get(kid).cloned()
    }

    /// Resolve a key that is active at the supplied Unix timestamp.
    pub fn resolve_at(&self, kid: &str, unix_timestamp: u64) -> Option<Arc<ResolvedKey>> {
        let now =
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix_timestamp).ok()?).ok()?;
        self.resolve_with_reason_at(kid, now).ok()
    }

    pub fn resolve_with_reason_at(
        &self,
        kid: &str,
        now: time::OffsetDateTime,
    ) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        let resolved = self.resolve(kid).ok_or(KeyResolveError::UnknownKid)?;
        if !resolved.enabled {
            return Err(KeyResolveError::PrincipalDisabled);
        }
        if resolved.not_before.is_some_and(|start| now < start) {
            return Err(KeyResolveError::NotYetValid);
        }
        if resolved.not_after.is_some_and(|end| now >= end) {
            return Err(KeyResolveError::Expired);
        }
        Ok(resolved)
    }

    pub fn issuer(&self, id: &str) -> Option<&IssuerEntry> {
        self.registry.issuers.iter().find(|issuer| issuer.id == id)
    }

    pub fn issuers(&self) -> &[IssuerEntry] {
        &self.registry.issuers
    }

    pub fn issuer_aggregation_id(&self, issuer: &str) -> Option<AggregationId> {
        self.issuer_aggregations.get(issuer).copied()
    }

    pub fn issuer_by_aggregation_id(&self, aggregation_id: AggregationId) -> Option<&str> {
        self.aggregation_issuers
            .get(&aggregation_id)
            .map(String::as_str)
    }

    pub fn admin(&self, id: &str) -> Option<&AdminEntry> {
        self.registry.admins.iter().find(|admin| admin.id == id)
    }

    pub fn has_admin_scope(&self, id: &str, scope: &str) -> bool {
        self.admin(id)
            .is_some_and(|admin| !admin.disabled && admin.scopes.iter().any(|value| value == scope))
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Every (principal id, kid, key material) across issuers and admins, so
    /// cross-source uniqueness checks cannot miss admin credentials. Key
    /// material is the canonical per-type string (RFC 7638 §7).
    pub fn all_principal_keys(&self) -> Vec<(&str, &str, String)> {
        let mut out = Vec::new();
        for issuer in &self.registry.issuers {
            for key in &issuer.keys {
                if let Ok(material) =
                    crate::domain::models::credential::canonical_jwk_material(&key.jwk)
                {
                    out.push((issuer.id.as_str(), key.kid.as_str(), material));
                }
            }
        }
        for admin in &self.registry.admins {
            for key in &admin.keys {
                if let Ok(material) =
                    crate::domain::models::credential::canonical_jwk_material(&key.jwk)
                {
                    out.push((admin.id.as_str(), key.kid.as_str(), material));
                }
            }
        }
        out
    }

    /// Whether any principal (issuer or admin) carries this id.
    pub fn has_principal_id(&self, id: &str) -> bool {
        self.registry.issuers.iter().any(|i| i.id == id)
            || self.registry.admins.iter().any(|a| a.id == id)
    }
}

fn parsed_window(value: Option<&str>) -> Option<time::OffsetDateTime> {
    value.map(|value| {
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .expect("registry validation parsed the key window")
    })
}

fn validate_schema(value: &Value) -> Result<(), RegistryError> {
    let schema: Value = serde_json::from_str(REGISTRY_SCHEMA)
        .map_err(|err| RegistryError::SchemaDefinition(err.to_string()))?;
    let compiled = jsonschema::validator_for(&schema)
        .map_err(|err| RegistryError::SchemaDefinition(err.to_string()))?;
    if let Some(error) = compiled.iter_errors(value).next() {
        return Err(RegistryError::Schema(error.to_string()));
    }
    Ok(())
}

fn validate_semantics(registry: &IssuerRegistry) -> Result<(), RegistryError> {
    let mut principal_ids = HashMap::new();
    let mut aggregations = HashMap::new();
    let mut keys = HashMap::new();
    let mut materials = HashMap::new();

    for issuer in &registry.issuers {
        if principal_ids.insert(&issuer.id, ()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "duplicate principal id `{}`",
                issuer.id
            )));
        }
        if aggregations.insert(issuer.aggregation_id, ()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "duplicate aggregation_id `{}`",
                issuer.aggregation_id
            )));
        }
        validate_keys(
            &issuer.id,
            issuer.keys.iter().map(Arc::as_ref),
            &mut keys,
            &mut materials,
        )?;
    }
    for admin in &registry.admins {
        if principal_ids.insert(&admin.id, ()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "duplicate principal id `{}`",
                admin.id
            )));
        }
        validate_keys(
            &admin.id,
            admin.keys.iter().map(Arc::as_ref),
            &mut keys,
            &mut materials,
        )?;
    }
    Ok(())
}

fn validate_keys<'a>(
    principal_id: &str,
    entries: impl IntoIterator<Item = &'a RegistryKey>,
    kids: &mut HashMap<String, ()>,
    materials: &mut HashMap<String, String>,
) -> Result<(), RegistryError> {
    for key in entries {
        let before = key
            .not_before
            .as_deref()
            .map(|value| {
                time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            })
            .transpose()
            .map_err(|err| RegistryError::Semantic(format!("invalid not_before: {err}")))?;
        let after = key
            .not_after
            .as_deref()
            .map(|value| {
                time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            })
            .transpose()
            .map_err(|err| RegistryError::Semantic(format!("invalid not_after: {err}")))?;
        if before
            .zip(after)
            .is_some_and(|(before, after)| before >= after)
        {
            return Err(RegistryError::Semantic(format!(
                "key `{}` for `{}` has not_before >= not_after",
                key.kid, principal_id
            )));
        }
        if kids.insert(key.kid.clone(), ()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "duplicate kid `{}`",
                key.kid
            )));
        }
        let public_key = validated_public_key(key)?;
        if public_key.key_id() != key.kid
            || key.alg.parse::<jsonwebtoken::Algorithm>().ok() != Some(public_key.algorithm())
        {
            return Err(RegistryError::Semantic(format!(
                "key `{}` does not match its kid or alg metadata",
                key.kid
            )));
        }
        let material = canonical_public_material(&key.jwk)?;
        if materials.insert(material, key.kid.clone()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "key material is reused by `{}`",
                key.kid
            )));
        }
    }
    Ok(())
}

/// Build the verification key exactly once, including the registry's `kid`
/// and `alg` metadata when the embedded public JWK intentionally omits them.
fn validated_public_key(key: &RegistryKey) -> Result<PublicJwk, RegistryError> {
    let mut jwk = key.jwk.clone();
    let object = jwk
        .as_object_mut()
        .ok_or_else(|| RegistryError::Semantic("JWK must be an object".into()))?;
    for (field, expected) in [("kid", key.kid.as_str()), ("alg", key.alg.as_str())] {
        if object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|actual| actual != expected)
        {
            return Err(RegistryError::Semantic(format!(
                "key `{}` has conflicting JWK {field} metadata",
                key.kid
            )));
        }
    }
    object.insert("kid".to_string(), Value::String(key.kid.clone()));
    object.insert("alg".to_string(), Value::String(key.alg.clone()));

    validate_ec_point(&jwk)?;
    PublicJwk::try_new(
        serde_json::to_vec(&jwk).map_err(|err| RegistryError::Semantic(err.to_string()))?,
    )
    .map_err(|err| RegistryError::Semantic(format!("key `{}`: {err}", key.kid)))
}

/// `jsonwebtoken` checks JWK shape and curve names, but point membership is a
/// cryptographic property. Parse the uncompressed SEC 1 point with AWS-LC so
/// malformed or off-curve EC keys cannot enter a trusted snapshot.
fn validate_ec_point(jwk: &Value) -> Result<(), RegistryError> {
    use aws_lc_rs::agreement::{ECDH_P256, ECDH_P384, ParsedPublicKey, UnparsedPublicKey};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let object = jwk
        .as_object()
        .ok_or_else(|| RegistryError::Semantic("JWK must be an object".into()))?;
    if object.get("kty").and_then(Value::as_str) != Some("EC") {
        return Ok(());
    }
    let (algorithm, coordinate_len) = match object.get("crv").and_then(Value::as_str) {
        Some("P-256") => (&ECDH_P256, 32),
        Some("P-384") => (&ECDH_P384, 48),
        _ => return Ok(()),
    };
    let coordinate = |field| {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| RegistryError::Semantic(format!("EC JWK is missing {field}")))
            .and_then(|value| {
                URL_SAFE_NO_PAD.decode(value).map_err(|error| {
                    RegistryError::Semantic(format!("invalid EC JWK {field}: {error}"))
                })
            })
    };
    let x = coordinate("x")?;
    let y = coordinate("y")?;
    if x.len() != coordinate_len || y.len() != coordinate_len {
        return Err(RegistryError::Semantic(format!(
            "EC JWK coordinates must be {coordinate_len} bytes for its curve"
        )));
    }
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend(x);
    point.extend(y);
    let _: ParsedPublicKey = UnparsedPublicKey::new(algorithm, point)
        .try_into()
        .map_err(|_| RegistryError::Semantic("EC JWK point is not on its curve".into()))?;
    Ok(())
}

/// Canonical string form of a JWK's normalized key parameters (RFC 7638 §7),
/// per-type members decoded and rendered byte-for-byte, member order ignored.
/// Uniqueness checks compare this, never a thumbprint.
fn canonical_public_material(jwk: &Value) -> Result<String, RegistryError> {
    crate::domain::models::credential::canonical_jwk_material(jwk).map_err(RegistryError::Semantic)
}

fn default_tier() -> String {
    "standard".to_string()
}

fn key_is_active(key: &RegistryKey, now: time::OffsetDateTime) -> bool {
    let parse = |value: Option<&str>| {
        value.map(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        })
    };
    let not_before = parse(key.not_before.as_deref()).transpose();
    let not_after = parse(key.not_after.as_deref()).transpose();
    matches!((not_before, not_after), (Ok(before), Ok(after))
        if before.is_none_or(|value| now >= value) && after.is_none_or(|value| now < value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = include_str!("../../../docs/schemas/issuers.v1.example.yaml");

    #[test]
    fn loads_example_and_resolves_keys() {
        let registry = IssuerRegistry::from_yaml(VALID).unwrap();
        assert_eq!(registry.key_count(), 3);
        assert_eq!(
            registry
                .resolve("QoRTRSkzlInq0eOmPqJwmZ5OS9pxkN_SIf5KgZP2F8M")
                .unwrap()
                .principal
                .id(),
            "6f1c2a9e-0b7d-4c1e-9a53-2f8d7e4b1c00"
        );
    }

    #[test]
    fn rejects_duplicate_kids() {
        let yaml = VALID.replace(
            "CO8SkimGYd7niQ8KCHGbmaO7KFA3ZvNwwYLTYLqyaZ8",
            "QoRTRSkzlInq0eOmPqJwmZ5OS9pxkN_SIf5KgZP2F8M",
        );
        let error = IssuerRegistry::from_yaml(&yaml).unwrap_err();
        assert!(error.to_string().contains("duplicate kid"));
    }

    #[test]
    fn rejects_duplicate_yaml_fields() {
        let yaml = VALID.replacen("version: 1", "version: 1\nversion: 1", 1);
        assert!(matches!(
            IssuerRegistry::from_yaml(&yaml),
            Err(RegistryError::Parse(_))
        ));
    }

    #[test]
    fn rejects_an_ec_point_that_is_not_on_its_curve() {
        let yaml = VALID.replace(
            "chypcSL_5pNDkx4dzv1dppYLpI_bYISWR_aw4JARneY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let error = IssuerRegistry::from_yaml(&yaml).unwrap_err();
        assert!(error.to_string().contains("point is not on its curve"));
    }

    #[test]
    fn rejects_private_jwk() {
        let yaml = VALID.replace(
            "          y: \"YwrO4sum6xF2PMUqSshAKVzLPJ-Ul87HgD7NGTo-oMA\"",
            "          d: private-material\n          y: \"YwrO4sum6xF2PMUqSshAKVzLPJ-Ul87HgD7NGTo-oMA\"",
        );
        assert!(matches!(
            IssuerRegistry::from_yaml(&yaml),
            Err(RegistryError::Schema(_))
        ));
    }

    #[test]
    fn canonical_key_material_ignores_jwk_member_order() {
        let first = serde_json::json!({
            "kty":"EC", "crv":"P-256",
            "x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
            "y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
        });
        let second: Value = serde_json::from_str(
            r#"{"y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","crv":"P-256","kty":"EC"}"#,
        )
        .unwrap();
        assert_eq!(
            canonical_public_material(&first).unwrap(),
            canonical_public_material(&second).unwrap()
        );
    }

    #[test]
    fn key_validity_windows_are_enforced() {
        let registry = IssuerRegistry::from_yaml(VALID).unwrap();
        assert!(
            registry
                .resolve_at("QoRTRSkzlInq0eOmPqJwmZ5OS9pxkN_SIf5KgZP2F8M", 1_791_763_201)
                .is_some()
        );
        assert!(
            registry
                .resolve_at("QoRTRSkzlInq0eOmPqJwmZ5OS9pxkN_SIf5KgZP2F8M", 1_791_763_199)
                .is_none()
        );
    }

    #[test]
    fn failed_reload_keeps_last_known_good_snapshot() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID).unwrap();
        let handle = RegistryHandle::load(file.path()).unwrap();
        assert_eq!(handle.snapshot().key_count(), 3);

        std::fs::write(file.path(), "version: invalid").unwrap();
        assert!(handle.reload().is_err());
        assert_eq!(handle.snapshot().key_count(), 3);
    }

    #[test]
    fn reload_rejects_a_changed_issuer_aggregation_id() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID).unwrap();
        let handle = RegistryHandle::load(file.path()).unwrap();
        let before = handle
            .snapshot()
            .issuer_aggregation_id("6f1c2a9e-0b7d-4c1e-9a53-2f8d7e4b1c00");

        std::fs::write(
            file.path(),
            VALID.replace(
                "0b8ef1c4-3c6a-4d2e-9f1a-5b7c9d2e4f60",
                "22222222-2222-4222-8222-222222222222",
            ),
        )
        .unwrap();
        assert!(handle.reload().is_err());
        assert_eq!(
            handle
                .snapshot()
                .issuer_aggregation_id("6f1c2a9e-0b7d-4c1e-9a53-2f8d7e4b1c00"),
            before
        );
    }

    #[test]
    fn reload_rejects_a_changed_aggregation_id_after_issuer_removal() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID).unwrap();
        let handle = RegistryHandle::load(file.path()).unwrap();

        let mut removed: serde_json::Value = serde_saphyr::from_str(VALID).unwrap();
        removed["issuers"] = serde_json::Value::Array(Vec::new());
        std::fs::write(file.path(), serde_saphyr::to_string(&removed).unwrap()).unwrap();
        handle.reload().unwrap();
        assert!(handle.snapshot().issuers().is_empty());

        let changed_id = "22222222-2222-4222-8222-222222222222";
        let readded = VALID.replace("0b8ef1c4-3c6a-4d2e-9f1a-5b7c9d2e4f60", changed_id);
        std::fs::write(file.path(), readded).unwrap();
        let error = handle.reload().unwrap_err();
        assert!(
            error.to_string().contains("aggregation_id") && error.to_string().contains("immutable")
        );
        assert!(handle.snapshot().issuers().is_empty());
    }

    #[test]
    fn reload_rejects_reusing_an_aggregation_id_for_a_different_issuer() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), VALID).unwrap();
        let handle = RegistryHandle::load(file.path()).unwrap();

        let mut removed: serde_json::Value = serde_saphyr::from_str(VALID).unwrap();
        removed["issuers"] = serde_json::Value::Array(Vec::new());
        std::fs::write(file.path(), serde_saphyr::to_string(&removed).unwrap()).unwrap();
        handle.reload().unwrap();

        let mut readded: serde_json::Value = serde_saphyr::from_str(VALID).unwrap();
        readded["issuers"][0]["id"] = serde_json::Value::String("different-issuer".into());
        std::fs::write(file.path(), serde_saphyr::to_string(&readded).unwrap()).unwrap();
        let error = handle.reload().unwrap_err();
        assert!(
            error.to_string().contains("issuer for aggregation_id")
                && error.to_string().contains("immutable")
        );
        assert!(handle.snapshot().issuers().is_empty());
    }

    #[test]
    fn admin_scopes_are_read_from_registry() {
        let registry = IssuerRegistry::from_yaml(VALID).unwrap();
        assert!(registry.has_admin_scope("portal-backend", "issuers:write"));
        assert!(!registry.has_admin_scope("portal-backend", "admin:root"));
    }
}
