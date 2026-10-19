//! Credential domain model, error types, and core domain business operations.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{fmt, str::FromStr};

use jsonwebtoken::{
    Algorithm,
    jwk::{AlgorithmParameters, Jwk},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Algorithms permitted by the management-token contract.
pub(crate) const MANAGEMENT_SIGNING_ALGORITHMS: [Algorithm; 4] = [
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
    Algorithm::PS256,
];

/// Domain errors encountered during issuer credential management.
///
/// `#[non_exhaustive]` so adding a variant stays patch-level instead of tripping
/// `cargo-semver-checks` (`enum_variant_added`).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid public JWK: {0}")]
    InvalidPublicJwk(String),
    #[error("credentials already exist for this issuer or key ID")]
    AlreadyExists,
    /// The write lost a lock race in storage and was rolled back; the request is
    /// safe to retry verbatim. Mirrors [`StatusListError::Contention`], `code`
    /// included, so the same driver error does not become a 409 on one write
    /// path and a 500 on the other.
    ///
    /// [`StatusListError::Contention`]: crate::domain::models::status_list::StatusListError::Contention
    #[error("the write lost a lock race ({code}) and can be retried unchanged")]
    Contention { code: &'static str },
    #[error("storage error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Unique issuer identifier string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Issuer(pub String);

impl From<String> for Issuer {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Issuer {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Opaque identifier that names an issuer's Status List Aggregation in public
/// URIs, so tokens never disclose the issuer identifier itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AggregationId(pub Uuid);

impl AggregationId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for AggregationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for AggregationId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

/// Validated JSON Web Key document bytes representing an issuer's public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct PublicJwk {
    bytes: Vec<u8>,
    jwk: Jwk,
    kid: String,
    algorithm: Algorithm,
}

impl TryFrom<Vec<u8>> for PublicJwk {
    type Error = CredentialError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

impl From<PublicJwk> for Vec<u8> {
    fn from(key: PublicJwk) -> Self {
        key.bytes
    }
}

impl PublicJwk {
    /// Create public JWK bytes from UTF-8 JSON.
    ///
    /// Ensures the payload is a supported public signing key.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
            CredentialError::InvalidPublicJwk(format!("expected UTF-8 JSON: {err}"))
        })?;
        if !value.is_object() {
            return Err(CredentialError::InvalidPublicJwk(
                "expected a JSON object".to_string(),
            ));
        }
        for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            if value.get(private_member).is_some() {
                return Err(CredentialError::InvalidPublicJwk(format!(
                    "private JWK member {private_member:?} is not permitted"
                )));
            }
        }
        let jwk: Jwk = serde_json::from_value(value)
            .map_err(|err| CredentialError::InvalidPublicJwk(format!("invalid JWK: {err}")))?;
        if jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| !matches!(usage, jsonwebtoken::jwk::PublicKeyUse::Signature))
        {
            return Err(CredentialError::InvalidPublicJwk(
                "use must be sig for a management signing key".into(),
            ));
        }
        if let AlgorithmParameters::RSA(parameters) = &jwk.algorithm {
            let modulus = URL_SAFE_NO_PAD.decode(&parameters.n).map_err(|_| {
                CredentialError::InvalidPublicJwk("invalid RSA modulus encoding".into())
            })?;
            let bits = modulus
                .iter()
                .position(|byte| *byte != 0)
                .map_or(0, |first| {
                    (modulus.len() - first - 1) * 8 + (8 - modulus[first].leading_zeros() as usize)
                });
            if !(2048..=8192).contains(&bits) {
                return Err(CredentialError::InvalidPublicJwk(
                    "RSA modulus must be between 2048 and 8192 bits".into(),
                ));
            }
        }
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(CredentialError::InvalidPublicJwk(
                "symmetric keys (kty=oct) are not permitted".to_string(),
            ));
        }
        let key_id = jwk
            .common
            .key_id
            .as_deref()
            .ok_or_else(|| CredentialError::InvalidPublicJwk("kid is required".to_string()))?;
        if key_id.is_empty() {
            return Err(CredentialError::InvalidPublicJwk(
                "kid must not be empty".to_string(),
            ));
        }
        if key_id.chars().count() > 255 {
            return Err(CredentialError::InvalidPublicJwk(
                "kid must not exceed 255 characters".to_string(),
            ));
        }
        let algorithm = jwk
            .common
            .key_algorithm
            .ok_or_else(|| CredentialError::InvalidPublicJwk("alg is required".to_string()))?;
        let algorithm = Algorithm::try_from(algorithm).map_err(|_| {
            CredentialError::InvalidPublicJwk("unsupported signing algorithm".into())
        })?;
        if !MANAGEMENT_SIGNING_ALGORITHMS.contains(&algorithm) {
            return Err(CredentialError::InvalidPublicJwk(
                "alg must be one of ES256, ES384, EdDSA, or PS256".to_string(),
            ));
        }
        let algorithm = match (&jwk.algorithm, algorithm) {
            (AlgorithmParameters::EllipticCurve(params), Algorithm::ES256)
                if matches!(params.curve, jsonwebtoken::jwk::EllipticCurve::P256) =>
            {
                Algorithm::ES256
            }
            (AlgorithmParameters::EllipticCurve(params), Algorithm::ES384)
                if matches!(params.curve, jsonwebtoken::jwk::EllipticCurve::P384) =>
            {
                Algorithm::ES384
            }
            (AlgorithmParameters::OctetKeyPair(params), Algorithm::EdDSA)
                if matches!(params.curve, jsonwebtoken::jwk::EllipticCurve::Ed25519) =>
            {
                Algorithm::EdDSA
            }
            (AlgorithmParameters::RSA(_), Algorithm::PS256) => Algorithm::PS256,
            _ => {
                return Err(CredentialError::InvalidPublicJwk(
                    "alg does not match the JWK key type or curve".to_string(),
                ));
            }
        };
        let kid = key_id.to_owned();
        jsonwebtoken::DecodingKey::from_jwk(&jwk).map_err(|err| {
            CredentialError::InvalidPublicJwk(format!("invalid verification key: {err}"))
        })?;
        Ok(Self {
            bytes,
            jwk,
            kid,
            algorithm,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn key_id(&self) -> &str {
        &self.kid
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }
}

/// Domain entity representing an issuer's registered public key credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: Issuer,
    pub public_key: PublicJwk,
}

#[cfg(test)]
mod tests {
    use super::PublicJwk;

    const VALID: &str = r#"{
        "kty":"EC", "crv":"P-256", "kid":"key-1", "alg":"ES256",
        "x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
        "y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
    }"#;

    #[test]
    fn validates_management_public_key_contract() {
        assert!(PublicJwk::try_new(VALID.as_bytes().to_vec()).is_ok());

        let missing_metadata = VALID.replace(", \"kid\":\"key-1\", \"alg\":\"ES256\"", "");
        assert!(PublicJwk::try_new(missing_metadata.into_bytes()).is_err());

        let private = VALID.replace("\"y\":", "\"d\":\"secret\", \"y\":");
        assert!(PublicJwk::try_new(private.into_bytes()).is_err());

        let oct = r#"{"kty":"oct","kid":"key-1","alg":"HS256","k":"secret"}"#;
        assert!(PublicJwk::try_new(oct.as_bytes().to_vec()).is_err());

        let key = VALID.replace("\"alg\":\"ES256\"", "\"alg\":\"ES384\"");
        assert!(PublicJwk::try_new(key.into_bytes()).is_err());
    }

    #[test]
    fn deserialization_enforces_public_key_validation() {
        let key = PublicJwk::try_new(VALID.as_bytes().to_vec()).unwrap();
        let encoded = serde_json::to_vec(&key).unwrap();
        let decoded: PublicJwk = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(decoded.key_id(), "key-1");
        assert_eq!(decoded.algorithm(), jsonwebtoken::Algorithm::ES256);
        let invalid = serde_json::to_vec(&b"{}".to_vec()).unwrap();
        assert!(serde_json::from_slice::<PublicJwk>(&invalid).is_err());
    }

    #[test]
    fn registration_rejects_encryption_keys_and_short_rsa_moduli() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let mut key: serde_json::Value = serde_json::from_str(VALID).unwrap();
        key["use"] = "enc".into();
        assert!(PublicJwk::try_new(serde_json::to_vec(&key).unwrap()).is_err());
        key["use"] = "sig".into();
        assert!(PublicJwk::try_new(serde_json::to_vec(&key).unwrap()).is_ok());
        let secret = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../test_data/gcloud_test_key.dummy.pem"
        ))
        .unwrap();
        let mut rsa = serde_json::to_value(
            jsonwebtoken::jwk::Jwk::from_encoding_key(&secret, jsonwebtoken::Algorithm::PS256)
                .unwrap(),
        )
        .unwrap();
        rsa["kid"] = "rsa-key".into();
        assert!(PublicJwk::try_new(serde_json::to_vec(&rsa).unwrap()).is_ok());
        for modulus in [
            vec![0xff; 128],
            {
                let mut n = vec![0; 128];
                n.extend(vec![0xff; 128]);
                n
            },
            vec![0; 256],
        ] {
            rsa["n"] = URL_SAFE_NO_PAD.encode(modulus).into();
            assert!(PublicJwk::try_new(serde_json::to_vec(&rsa).unwrap()).is_err());
        }
    }
}
