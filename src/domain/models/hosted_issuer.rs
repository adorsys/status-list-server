//! Hosted-profile issuer model (ADR 0002): issuers registered through
//! onboarding and persisted in durable storage. Their public keys resolve
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
    Disabled,
}

impl HostedIssuerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedIssuerState::Active => "active",
            HostedIssuerState::Disabled => "disabled",
        }
    }
}

/// A hosted-profile issuer with the identity data authentication needs plus
/// the operator-managed metadata the admin surface edits. `id` is assigned by
/// the server (UUID v4) and never chosen by the issuer; `aggregation_id` is
/// generated once at creation and is immutable (ADR 0002, Identifiers).
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

impl HostedIssuer {
    /// Whether the issuer may authenticate right now: the persisted state is
    /// active and a configured expiry has not passed.
    pub fn is_currently_enabled(&self, now: OffsetDateTime) -> bool {
        self.state == HostedIssuerState::Active && self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

/// A hosted issuer's signing key, mirroring one `issuer_keys` row. The public
/// key is validated by [`PublicJwk`], the same contract used for every trust
/// source.
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
/// `issuer_keys.state`; a revoked key makes resolution fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedIssuerKeyState {
    Active,
    Revoked,
}

impl HostedIssuerKeyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedIssuerKeyState::Active => "active",
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
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HostedIssuerError {
    #[error("hosted issuer or key not found")]
    NotFound,
    #[error("a hosted issuer or key with this id or kid already exists")]
    AlreadyExists,
    /// RFC 7638 §7: equivalencing key material by thumbprint is unsound, so
    /// reuse is detected by comparing normalized key parameters instead. The
    /// owner is logged server-side and never returned to the caller.
    #[error("key material was already registered by another issuer")]
    KeyMaterialReused,
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
    /// A persisted hosted row is malformed and can never parse. A permanent
    /// data fault: authentication fails closed for that key but the backend
    /// itself is healthy, so this is not a retryable 503.
    #[error("stored hosted issuer data is corrupt: {0}")]
    Corrupt(String),
    #[error("the write lost a lock race ({code}) and can be retried unchanged")]
    Contention { code: &'static str },
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
        if self.key.state != HostedIssuerKeyState::Active {
            return Err(KeyResolveError::Revoked);
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
    fn disabled_issuer_fails_closed() {
        let entry = entry_with(
            HostedIssuerState::Disabled,
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
        assert!(matches!(
            entry.resolved_key(now()),
            Err(KeyResolveError::PrincipalDisabled)
        ));
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
