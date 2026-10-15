//! Operator-managed issuer trust registry.
//!
//! This module loads, validates, and resolves the trusted keys used by
//! authentication.

use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const REGISTRY_SCHEMA: &str = include_str!("../../../docs/schemas/issuers.v1.schema.json");

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("failed to read issuer registry: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse issuer registry YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("issuer registry schema validation failed: {0}")]
    Schema(String),
    #[error("issuer registry semantic validation failed: {0}")]
    Semantic(String),
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
    pub keys: Vec<RegistryKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminEntry {
    pub id: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
    pub keys: Vec<RegistryKey>,
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
pub struct ResolvedKey {
    pub principal_id: String,
    pub key: RegistryKey,
}

impl ResolvedKey {
    pub fn issuer<'a>(&self, registry: &'a ValidatedRegistry) -> Option<&'a IssuerEntry> {
        registry.issuer(&self.principal_id)
    }

    pub fn admin<'a>(&self, registry: &'a ValidatedRegistry) -> Option<&'a AdminEntry> {
        registry.admin(&self.principal_id)
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedRegistry {
    registry: Arc<IssuerRegistry>,
    keys: Arc<HashMap<String, ResolvedKey>>,
}

/// Atomically replaceable, last-known-good registry used by request handlers.
#[derive(Debug)]
pub struct RegistryHandle {
    path: PathBuf,
    active: ArcSwap<ValidatedRegistry>,
}

/// Port used by authentication to resolve an operator-trusted signing key.
pub trait IssuerKeyResolver: Send + Sync {
    fn resolve(&self, kid: &str) -> Option<ResolvedKey>;
}

/// File-backed implementation name used in the issue and operational docs.
pub type StaticFileRegistry = RegistryHandle;

impl RegistryHandle {
    pub fn from_yaml(content: &str) -> Result<Self, RegistryError> {
        Ok(Self {
            path: PathBuf::from("<memory>"),
            active: ArcSwap::from_pointee(IssuerRegistry::from_yaml(content)?),
        })
    }

    pub fn empty() -> Self {
        Self {
            path: PathBuf::from("<empty>"),
            active: ArcSwap::from_pointee(
                IssuerRegistry::from_yaml("version: 1\nissuers: []\nadmins: []\n")
                    .expect("empty registry is valid"),
            ),
        }
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        let registry = IssuerRegistry::from_file(&path)?;
        Ok(Self {
            path,
            active: ArcSwap::from_pointee(registry),
        })
    }

    pub fn snapshot(&self) -> Arc<ValidatedRegistry> {
        self.active.load_full()
    }

    pub fn reload(&self) -> Result<(), RegistryError> {
        let registry = IssuerRegistry::from_file(&self.path)?;
        self.active.store(Arc::new(registry));
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl IssuerKeyResolver for RegistryHandle {
    fn resolve(&self, kid: &str) -> Option<ResolvedKey> {
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let timestamp = u64::try_from(timestamp).ok()?;
        self.snapshot().resolve_at(kid, timestamp).cloned()
    }
}

impl IssuerRegistry {
    pub fn from_file(path: impl AsRef<Path>) -> Result<ValidatedRegistry, RegistryError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    pub fn from_yaml(content: &str) -> Result<ValidatedRegistry, RegistryError> {
        let yaml: serde_yaml::Value = serde_yaml::from_str(content)?;
        let json: Value =
            serde_json::to_value(&yaml).map_err(|err| RegistryError::Schema(err.to_string()))?;
        validate_schema(&json)?;
        let registry: Self = serde_yaml::from_value(yaml)?;
        validate_semantics(&registry)?;
        let now = time::OffsetDateTime::now_utc();
        for issuer in &registry.issuers {
            if !issuer.keys.iter().any(|key| key_is_active(key, now)) {
                tracing::warn!(issuer = %issuer.id, "issuer has no currently valid signing key");
            }
        }

        let mut keys = HashMap::new();
        for issuer in &registry.issuers {
            for key in &issuer.keys {
                keys.insert(
                    key.kid.clone(),
                    ResolvedKey {
                        principal_id: issuer.id.clone(),
                        key: key.clone(),
                    },
                );
            }
        }
        for admin in &registry.admins {
            for key in &admin.keys {
                keys.insert(
                    key.kid.clone(),
                    ResolvedKey {
                        principal_id: admin.id.clone(),
                        key: key.clone(),
                    },
                );
            }
        }

        Ok(ValidatedRegistry {
            registry: Arc::new(registry),
            keys: Arc::new(keys),
        })
    }
}

impl ValidatedRegistry {
    pub fn resolve(&self, kid: &str) -> Option<&ResolvedKey> {
        self.keys.get(kid)
    }

    /// Resolve a key that is active at the supplied Unix timestamp.
    pub fn resolve_at(&self, kid: &str, unix_timestamp: u64) -> Option<&ResolvedKey> {
        let resolved = self.resolve(kid)?;
        let active = |key: &RegistryKey| {
            let now =
                time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix_timestamp).ok()?)
                    .ok()?;
            let not_before = key
                .not_before
                .as_deref()
                .map(|value| {
                    time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                })
                .transpose()
                .ok()?;
            let not_after = key
                .not_after
                .as_deref()
                .map(|value| {
                    time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                })
                .transpose()
                .ok()?;
            Some(
                not_before.is_none_or(|value| now >= value)
                    && not_after.is_none_or(|value| now < value),
            )
        };
        let enabled = self
            .issuer(&resolved.principal_id)
            .map(|issuer| !issuer.disabled)
            .or_else(|| {
                self.registry
                    .admins
                    .iter()
                    .find(|admin| admin.id == resolved.principal_id)
                    .map(|admin| !admin.disabled)
            })
            .unwrap_or(false);
        if enabled && active(&resolved.key).unwrap_or(false) {
            Some(resolved)
        } else {
            None
        }
    }

    pub fn issuer(&self, id: &str) -> Option<&IssuerEntry> {
        self.registry.issuers.iter().find(|issuer| issuer.id == id)
    }

    pub fn issuers(&self) -> &[IssuerEntry] {
        &self.registry.issuers
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
        validate_keys(&issuer.id, &issuer.keys, &mut keys, &mut materials)?;
    }
    for admin in &registry.admins {
        if principal_ids.insert(&admin.id, ()).is_some() {
            return Err(RegistryError::Semantic(format!(
                "duplicate principal id `{}`",
                admin.id
            )));
        }
        validate_keys(&admin.id, &admin.keys, &mut keys, &mut materials)?;
    }
    Ok(())
}

fn validate_keys(
    principal_id: &str,
    entries: &[RegistryKey],
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
        let mut jwk_for_validation = key.jwk.clone();
        if let Some(object) = jwk_for_validation.as_object_mut() {
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
        }
        let public_key = crate::domain::models::credential::PublicJwk::try_new(
            serde_json::to_vec(&jwk_for_validation)
                .map_err(|err| RegistryError::Semantic(err.to_string()))?,
        )
        .map_err(|err| RegistryError::Semantic(format!("key `{}`: {err}", key.kid)))?;
        if public_key.key_id() != key.kid || format!("{:?}", public_key.algorithm()) != key.alg {
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

fn canonical_public_material(jwk: &Value) -> Result<String, RegistryError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let object = jwk
        .as_object()
        .ok_or_else(|| RegistryError::Semantic("JWK must be an object".into()))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| RegistryError::Semantic("JWK is missing kty".into()))?;
    let string = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| RegistryError::Semantic(format!("JWK is missing {field}")))
    };
    let decode = |field: &str| {
        URL_SAFE_NO_PAD
            .decode(string(field)?)
            .map_err(|error| RegistryError::Semantic(format!("invalid JWK {field}: {error}")))
    };
    match kty {
        "EC" => Ok(format!(
            "EC|{}|{}|{}",
            string("crv")?,
            hex::encode(decode("x")?),
            hex::encode(decode("y")?)
        )),
        "RSA" => {
            let mut modulus = decode("n")?;
            let mut exponent = decode("e")?;
            let first_modulus_byte = modulus
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(modulus.len());
            let first_exponent_byte = exponent
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(exponent.len());
            modulus.drain(..first_modulus_byte);
            exponent.drain(..first_exponent_byte);
            Ok(format!(
                "RSA|{}|{}",
                hex::encode(modulus),
                hex::encode(exponent)
            ))
        }
        "OKP" => Ok(format!(
            "OKP|{}|{}",
            string("crv")?,
            hex::encode(decode("x")?)
        )),
        _ => Err(RegistryError::Semantic(format!(
            "unsupported JWK kty `{kty}`"
        ))),
    }
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
                .principal_id,
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
    fn admin_scopes_are_read_from_registry() {
        let registry = IssuerRegistry::from_yaml(VALID).unwrap();
        assert!(registry.has_admin_scope("portal-backend", "issuers:write"));
        assert!(!registry.has_admin_scope("portal-backend", "admin:root"));
    }
}
