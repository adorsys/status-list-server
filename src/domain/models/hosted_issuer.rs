//! Hosted-profile issuer model (ADR 0002): issuers held in durable storage
//! rather than the static registry. Their public keys resolve
//! through the same port as the static registry's, so authentication never
//! depends on where a key came from.

use std::sync::Arc;
use time::OffsetDateTime;

use crate::domain::models::credential::{
    AggregationId, KeyResolveError, Principal, PublicJwk, ResolvedKey,
};

/// Lifecycle of a hosted issuer row. Stored as a string in `issuers.state`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedIssuerState {
    Active,
    Suspended,
}

impl HostedIssuerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedIssuerState::Active => "active",
            HostedIssuerState::Suspended => "suspended",
        }
    }
}

/// A hosted-profile issuer with the identity data authentication needs plus
/// the operator-managed metadata. `id` is assigned by the server (UUID v4) and
/// never chosen by the issuer; `aggregation_id` is generated once at creation
/// and is immutable (ADR 0002, Identifiers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedIssuer {
    pub id: String,
    pub display_name: Option<String>,
    pub tier: String,
    pub state: HostedIssuerState,
    pub owner: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub version: u64,
    pub aggregation_id: AggregationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedIssuerLifecycleState {
    Active,
    Suspended,
    Expired,
}

impl HostedIssuer {
    /// Expiry is derived at verification time, without a cleanup job.
    /// Suspension wins over expiry so an operator never sees a suspended
    /// issuer reported as merely expired.
    pub fn lifecycle_state(&self, now: OffsetDateTime) -> HostedIssuerLifecycleState {
        if self.state == HostedIssuerState::Suspended {
            HostedIssuerLifecycleState::Suspended
        } else if self.expires_at.is_some_and(|expiry| now >= expiry) {
            HostedIssuerLifecycleState::Expired
        } else {
            HostedIssuerLifecycleState::Active
        }
    }

    /// Whether the issuer may authenticate right now: the persisted state is
    /// active and a configured expiry has not passed.
    pub fn is_currently_enabled(&self, now: OffsetDateTime) -> bool {
        self.lifecycle_state(now) == HostedIssuerLifecycleState::Active
    }
}

/// Metadata filters applied before bounding an admin issuer page.
#[derive(Clone, Debug, Default)]
pub struct HostedIssuerFilter {
    pub tier: Option<String>,
    pub state: Option<HostedIssuerReadState>,
    pub owner: Option<String>,
}

/// Admin-visible lifecycle derived from persisted state and expiry.
#[derive(Clone, Copy, Debug)]
pub enum HostedIssuerReadState {
    Active,
    Suspended,
    Expired,
}

/// Input to create a hosted issuer through `HostedIssuerService`. Identifiers
/// (`id`, `aggregation_id`, `created_at`, `version`) are assigned by the
/// server, never by the caller (ADR 0002, Identifiers), so this carries only
/// operator-supplied metadata. `expires_at` is required: hosted issuer
/// credentials always expire (ADR 0002, Limits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewHostedIssuer {
    pub display_name: Option<String>,
    pub tier: String,
    pub owner: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// Input to register a hosted issuer key through `HostedIssuerService`. The kid
/// is assigned by the server, so `jwk` carries no `kid`; `created_at` is
/// assigned too. Typed as a JSON object map so that a non-object body is
/// rejected before it reaches `register_key`, ruling out the `IndexMut` panic
/// that `serde_json::Value` would cause on strings, arrays, and numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewHostedIssuerKey {
    pub issuer_id: String,
    pub jwk: serde_json::Map<String, serde_json::Value>,
    pub not_before: Option<OffsetDateTime>,
    pub not_after: Option<OffsetDateTime>,
}

/// A hosted issuer's signing key mirroring one `issuer_keys` row, with the
/// public key validated by [`PublicJwk`] like every trust source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedIssuerKey {
    pub kid: String,
    pub issuer_id: String,
    pub jwk: PublicJwk,
    /// When the key row itself was created, independent of its validity window.
    pub created_at: OffsetDateTime,
    pub not_before: Option<OffsetDateTime>,
    pub not_after: Option<OffsetDateTime>,
    pub state: HostedIssuerKeyState,
}

/// Lifecycle of a hosted issuer key row. Stored as a string in
/// `issuer_keys.state`; a revoked key makes resolution fail closed. `Reserved`
/// holds a carried-over legacy kid and material so the identifier is kept but
/// nothing authenticates until an operator adopts the key into the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedIssuerKeyState {
    Active,
    Reserved,
    Revoked,
}

impl HostedIssuerKeyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedIssuerKeyState::Active => "active",
            HostedIssuerKeyState::Reserved => "reserved",
            HostedIssuerKeyState::Revoked => "revoked",
        }
    }
}

impl HostedIssuerKey {
    /// Whether the key is inside its validity window at `now`.
    pub fn is_currently_valid(&self, now: OffsetDateTime) -> bool {
        self.state == HostedIssuerKeyState::Active
            && self.not_before.is_none_or(|start| now >= start)
            && self.not_after.is_none_or(|end| now < end)
    }
}

/// Why a hosted issuer or key could not be created, updated, or read.
///
/// Mirrors [`CredentialError`]: `AlreadyExists` is the client-visible 409 for
/// identifier clashes, `Contention { code }` carries the driver discriminator
/// for a retryable lock race, and `Backend` wraps everything else. Uniqueness
/// is enforced by storage keys and constraints, never by a pre-check.
///
/// [`CredentialError`]: crate::domain::models::credential::CredentialError
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HostedIssuerError {
    #[error("hosted issuer or key not found")]
    NotFound,
    #[error("a hosted issuer or key with this id or kid already exists")]
    AlreadyExists,
    /// RFC 7638 §7: reuse is rejected by comparing normalized key parameters;
    /// the owner is logged server-side, never returned to the caller.
    #[error("key material was already registered by another issuer")]
    KeyMaterialReused,
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
    #[error("invalid expiry: {0}")]
    InvalidExpiry(String),
    #[error("issuer version has changed; read the current state before retrying")]
    VersionMismatch,
    /// A persisted hosted row is malformed and can never parse: a permanent
    /// data fault that fails closed for that key, not a retryable 503.
    #[error("stored hosted issuer data is corrupt: {0}")]
    Corrupt(String),
    #[error("the write lost a lock race ({code}) and can be retried unchanged")]
    Contention { code: &'static str },
    /// The store could not be reached: retry later with the same request.
    #[error("the issuer store is currently unavailable")]
    Unavailable,
    #[error("storage error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A hosted key resolved through storage: the owning issuer's identity data
/// alongside the key, so authentication can build a [`ResolvedKey`] without a
/// second lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedIssuerKeyEntry {
    pub issuer: HostedIssuer,
    pub key: HostedIssuerKey,
}

impl HostedIssuerKeyEntry {
    /// Resolve to the same shape the static registry produces.
    pub fn resolved_key(&self, now: OffsetDateTime) -> Result<Arc<ResolvedKey>, KeyResolveError> {
        if !self.issuer.is_currently_enabled(now) {
            return Err(KeyResolveError::PrincipalDisabled);
        }
        match self.key.state {
            HostedIssuerKeyState::Active => {}
            HostedIssuerKeyState::Reserved => return Err(KeyResolveError::Reserved),
            HostedIssuerKeyState::Revoked => return Err(KeyResolveError::Revoked),
        }
        if !self.key.is_currently_valid(now) {
            if self.key.not_before.is_some_and(|start| now < start) {
                return Err(KeyResolveError::NotYetValid);
            }
            return Err(KeyResolveError::Expired);
        }
        Ok(Arc::new(ResolvedKey {
            principal: Principal::Issuer {
                id: self.issuer.id.clone(),
                aggregation_id: self.issuer.aggregation_id,
            },
            public_key: Arc::new(self.key.jwk.clone()),
            enabled: true,
            not_before: self.key.not_before,
            not_after: self.key.not_after,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::KeyResolveError;
    const EC_JWK: &str = r#"{
        "kty": "EC", "crv": "P-256", "kid": "portal-key", "alg": "ES256",
        "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
        "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
    }"#;

    fn entry_with(
        issuer_state: HostedIssuerState,
        issuer_expiry: Option<OffsetDateTime>,
        key_state: HostedIssuerKeyState,
        window: (Option<OffsetDateTime>, Option<OffsetDateTime>),
    ) -> HostedIssuerKeyEntry {
        let not_before = window.0;
        let not_after = window.1;
        HostedIssuerKeyEntry {
            issuer: HostedIssuer {
                id: "00000000-0000-4000-8000-000000000001".into(),
                display_name: None,
                tier: "standard".into(),
                state: issuer_state,
                owner: None,
                created_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: issuer_expiry,
                version: 1,
                aggregation_id: AggregationId::generate(),
            },
            key: HostedIssuerKey {
                kid: "portal-key".into(),
                issuer_id: "00000000-0000-4000-8000-000000000001".into(),
                jwk: PublicJwk::try_new(EC_JWK.as_bytes().to_vec()).unwrap(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                not_before,
                not_after,
                state: key_state,
            },
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_791_763_200).unwrap()
    }

    #[test]
    fn suspended_issuer_fails_closed() {
        let entry = entry_with(
            HostedIssuerState::Suspended,
            None,
            HostedIssuerKeyState::Active,
            (None, None),
        );
        assert!(matches!(
            entry.resolved_key(now()),
            Err(KeyResolveError::PrincipalDisabled)
        ));
    }

    #[test]
    fn expired_issuer_fails_closed() {
        let expired = now() - time::Duration::seconds(1);
        let entry = entry_with(
            HostedIssuerState::Active,
            Some(expired),
            HostedIssuerKeyState::Active,
            (None, None),
        );
        assert_eq!(
            entry.issuer.lifecycle_state(now()),
            HostedIssuerLifecycleState::Expired
        );
        assert!(matches!(
            entry.resolved_key(now()),
            Err(KeyResolveError::PrincipalDisabled)
        ));
    }

    #[test]
    fn suspension_takes_precedence_over_expiry() {
        let entry = entry_with(
            HostedIssuerState::Suspended,
            Some(now() - time::Duration::seconds(1)),
            HostedIssuerKeyState::Active,
            (None, None),
        );
        assert_eq!(
            entry.issuer.lifecycle_state(now()),
            HostedIssuerLifecycleState::Suspended
        );
    }

    #[test]
    fn revoked_key_fails_closed() {
        let entry = entry_with(
            HostedIssuerState::Active,
            None,
            HostedIssuerKeyState::Revoked,
            (None, None),
        );
        assert!(matches!(
            entry.resolved_key(now()),
            Err(KeyResolveError::Revoked)
        ));
    }

    #[test]
    fn key_window_is_enforced() {
        let before = now() - time::Duration::seconds(1);
        let entry = entry_with(
            HostedIssuerState::Active,
            None,
            HostedIssuerKeyState::Active,
            (Some(now()), None),
        );
        assert!(matches!(
            entry.resolved_key(before),
            Err(KeyResolveError::NotYetValid)
        ));
        let entry = entry_with(
            HostedIssuerState::Active,
            None,
            HostedIssuerKeyState::Active,
            (None, Some(now())),
        );
        assert!(matches!(
            entry.resolved_key(now()),
            Err(KeyResolveError::Expired)
        ));
    }

    #[test]
    fn active_entry_resolves_an_issuer_principal() {
        let aggregation_id = AggregationId::generate();
        let mut entry = entry_with(
            HostedIssuerState::Active,
            None,
            HostedIssuerKeyState::Active,
            (None, None),
        );
        entry.issuer.aggregation_id = aggregation_id;
        let resolved = entry.resolved_key(now()).unwrap();
        match &resolved.principal {
            Principal::Issuer {
                id,
                aggregation_id: agg,
            } => {
                assert_eq!(id, &entry.issuer.id);
                assert_eq!(*agg, aggregation_id);
            }
            Principal::Admin { .. } => panic!("hosted issuer must resolve as an issuer principal"),
        }
        assert!(resolved.enabled);
    }
}
