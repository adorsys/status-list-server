use std::fmt;
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Standard Cryptographic OIDs
const OID_ID_EC_PUBLIC_KEY: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ED25519: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_RSA_ENCRYPTION: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Algorithms supported for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// EdDSA using Curve25519.
    EdDsa,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
}

impl SigningAlgorithm {
    /// Return the standard JOSE algorithm name (e.g. "ES256", "RS256").
    pub const fn jose_name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }

    /// Return the IANA COSE algorithm integer identifier.
    pub const fn cose_id(&self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.jose_name())
    }
}

impl From<SigningAlgorithm> for jsonwebtoken::Algorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
            SigningAlgorithm::Es384 => jsonwebtoken::Algorithm::ES384,
            SigningAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
            SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
        }
    }
}

impl From<SigningAlgorithm> for coset::iana::Algorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::Es256 => coset::iana::Algorithm::ES256,
            SigningAlgorithm::Es384 => coset::iana::Algorithm::ES384,
            SigningAlgorithm::EdDsa => coset::iana::Algorithm::EdDSA,
            SigningAlgorithm::Rs256 => coset::iana::Algorithm::RS256,
        }
    }
}

/// Errors occurring during cryptographic key management and signing.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] aws_lc_rs::error::Unspecified),

    #[error("Cryptographic key was rejected: {0}")]
    KeyRejected(#[from] aws_lc_rs::error::KeyRejected),

    #[error("PEM decoding failed: {0}")]
    Pem(#[from] pem::PemError),

    #[error("PKCS#8 structure error: {0}")]
    Pkcs8(#[from] pkcs8::Error),

    #[error("ASN.1 DER error: {0}")]
    Der(#[from] der::Error),

    #[error("Unsupported PEM tag: {0}")]
    UnsupportedPemTag(String),

    #[error("Unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Unsupported elliptic curve: {0}")]
    UnsupportedCurve(String),

    #[error("Automatic key generation is not supported for algorithm: {0}")]
    UnsupportedKeygen(String),
}

/// Decoupled signing trait isolating consumers from low-level cryptographic backends.
pub trait TokenSigner: Send + Sync {
    /// Return the algorithm associated with this signer.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Sign arbitrary payload bytes returning raw signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Return raw public key bytes for X.509 certificate validation.
    fn public_key_bytes(&self) -> &[u8];
}

/// Unified signing key supporting ECDSA (P-256, P-384), Ed25519, and RSA (RS256).
pub struct SigningKey {
    algorithm: SigningAlgorithm,
    inner: SigningKeyInner,
    public_key: Box<[u8]>,
}

struct SigningKeyInner {
    pair: KeyPairInner,
    encoding_key: jsonwebtoken::EncodingKey,
    rng: SystemRandom,
}

enum KeyPairInner {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

impl SigningKeyInner {
    fn to_pkcs8_der(&self) -> Result<Box<[u8]>, Error> {
        use aws_lc_rs::encoding::AsDer;
        match &self.pair {
            KeyPairInner::Ecdsa(kp) => Ok(kp.to_pkcs8v1()?.as_ref().into()),
            KeyPairInner::Ed25519(kp) => Ok(kp.to_pkcs8v1()?.as_ref().into()),
            KeyPairInner::Rsa(kp) => Ok(kp.as_der()?.as_ref().into()),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a new random signing key for the specified algorithm.
    pub fn generate(algorithm: SigningAlgorithm) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        match algorithm {
            SigningAlgorithm::Es256 => {
                let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
                Self::from_pkcs8_der(doc.as_ref())
            }
            SigningAlgorithm::Es384 => {
                let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)?;
                Self::from_pkcs8_der(doc.as_ref())
            }
            SigningAlgorithm::EdDsa => {
                let doc = Ed25519KeyPair::generate_pkcs8(&rng)?;
                Self::from_pkcs8_der(doc.as_ref())
            }
            SigningAlgorithm::Rs256 => Err(Error::UnsupportedKeygen("RS256".into())),
        }
    }

    /// Load and automatically detect signing key from PEM string (supports PKCS#8, SEC1, or PKCS#1 format).
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        let parsed = pem::parse(pem_str.as_bytes())?;

        match parsed.tag() {
            "PRIVATE KEY" => Self::from_pkcs8_der(parsed.contents()),
            "EC PRIVATE KEY" => {
                let pkcs8_der = convert_sec1_to_pkcs8(parsed.contents())?;
                Self::from_pkcs8_der(&pkcs8_der)
            }
            "RSA PRIVATE KEY" => {
                let pkcs8_der = convert_pkcs1_to_pkcs8(parsed.contents())?;
                Self::from_pkcs8_der(&pkcs8_der)
            }
            other => Err(Error::UnsupportedPemTag(other.into())),
        }
    }

    /// Parse PKCS#8 DER bytes and auto-detect algorithm.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let pki = pkcs8::PrivateKeyInfoRef::from_der(der)?;
        let algorithm = detect_pkcs8_algorithm(&pki)?;
        let rng = SystemRandom::new();

        let (pair, encoding_key, public_key) = match algorithm {
            SigningAlgorithm::Es256 => {
                let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)?;
                let enc_key = jsonwebtoken::EncodingKey::from_ec_der(der);
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ecdsa(kp), enc_key, pub_bytes.into())
            }
            SigningAlgorithm::Es384 => {
                let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, der)?;
                let enc_key = jsonwebtoken::EncodingKey::from_ec_der(der);
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ecdsa(kp), enc_key, pub_bytes.into())
            }
            SigningAlgorithm::EdDsa => {
                let kp = Ed25519KeyPair::from_pkcs8(der)?;
                let enc_key = jsonwebtoken::EncodingKey::from_ed_der(der);
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ed25519(kp), enc_key, pub_bytes.into())
            }
            SigningAlgorithm::Rs256 => {
                let kp = RsaKeyPair::from_pkcs8(der)?;
                let enc_key = jsonwebtoken::EncodingKey::from_rsa_der(pki.private_key.as_bytes());
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Rsa(kp), enc_key, pub_bytes.into())
            }
        };

        Ok(Self {
            algorithm,
            inner: SigningKeyInner {
                pair,
                encoding_key,
                rng,
            },
            public_key,
        })
    }

    /// Convert to PKCS#8 PEM string.
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        let p = pem::Pem::new("PRIVATE KEY", self.inner.to_pkcs8_der()?);
        #[cfg(windows)]
        return Ok(pem::encode_config(
            &p,
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::CRLF),
        ));

        #[cfg(not(windows))]
        Ok(pem::encode_config(
            &p,
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        ))
    }

    /// Sign arbitrary payload bytes using the configured backend algorithm.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.inner.pair {
            KeyPairInner::Ecdsa(kp) => {
                let sig = kp.sign(&self.inner.rng, data)?;
                Ok(sig.as_ref().to_vec())
            }
            KeyPairInner::Ed25519(kp) => {
                let sig = kp.sign(data);
                Ok(sig.as_ref().to_vec())
            }
            KeyPairInner::Rsa(kp) => {
                let mut sig = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &self.inner.rng, data, &mut sig)?;
                Ok(sig)
            }
        }
    }

    /// Return the algorithm of this key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Return raw public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

impl From<SigningKey> for jsonwebtoken::EncodingKey {
    fn from(key: SigningKey) -> Self {
        key.inner.encoding_key
    }
}

impl AsRef<jsonwebtoken::EncodingKey> for SigningKey {
    fn as_ref(&self) -> &jsonwebtoken::EncodingKey {
        &self.inner.encoding_key
    }
}

impl TokenSigner for SigningKey {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign(data)
    }

    fn public_key_bytes(&self) -> &[u8] {
        self.public_key_bytes()
    }
}

impl<T: TokenSigner + ?Sized> TokenSigner for Arc<T> {
    fn algorithm(&self) -> SigningAlgorithm {
        (**self).algorithm()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).sign(data)
    }

    fn public_key_bytes(&self) -> &[u8] {
        (**self).public_key_bytes()
    }
}

fn detect_pkcs8_algorithm(pki: &pkcs8::PrivateKeyInfoRef<'_>) -> Result<SigningAlgorithm, Error> {
    if pki.algorithm.oid == OID_ED25519 {
        return Ok(SigningAlgorithm::EdDsa);
    }
    if pki.algorithm.oid == OID_RSA_ENCRYPTION {
        return Ok(SigningAlgorithm::Rs256);
    }
    if pki.algorithm.oid == OID_ID_EC_PUBLIC_KEY {
        let params = pki.algorithm.parameters.ok_or_else(|| {
            Error::UnsupportedAlgorithm("missing curve parameters in EC key".into())
        })?;
        let curve_oid: pkcs8::ObjectIdentifier = params.decode_as()?;
        if curve_oid == OID_SECP256R1 {
            return Ok(SigningAlgorithm::Es256);
        }
        if curve_oid == OID_SECP384R1 {
            return Ok(SigningAlgorithm::Es384);
        }
        return Err(Error::UnsupportedCurve(curve_oid.to_string()));
    }

    Err(Error::UnsupportedAlgorithm(pki.algorithm.oid.to_string()))
}

fn convert_sec1_to_pkcs8(sec1_der: &[u8]) -> Result<Vec<u8>, Error> {
    let sec1_key = sec1::EcPrivateKey::from_der(sec1_der)?;
    let curve_oid = match sec1_key.parameters {
        Some(sec1::EcParameters::NamedCurve(oid)) => oid,
        _ => {
            return Err(Error::UnsupportedAlgorithm(
                "unsupported curve parameters in EC key".into(),
            ));
        }
    };
    let octet_str = der::asn1::OctetStringRef::new(sec1_der)?;

    let pki = pkcs8::PrivateKeyInfoRef::new(
        pkcs8::spki::AlgorithmIdentifierRef {
            oid: OID_ID_EC_PUBLIC_KEY,
            parameters: Some(der::AnyRef::from(&curve_oid)),
        },
        octet_str,
    );
    Ok(pki.to_der()?)
}

fn convert_pkcs1_to_pkcs8(pkcs1_der: &[u8]) -> Result<Vec<u8>, Error> {
    let octet_str = der::asn1::OctetStringRef::new(pkcs1_der)?;
    let pki = pkcs8::PrivateKeyInfoRef::new(
        pkcs8::spki::AlgorithmIdentifierRef {
            oid: OID_RSA_ENCRYPTION,
            parameters: Some(der::AnyRef::from(der::asn1::Null)),
        },
        octet_str,
    );
    Ok(pki.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256,
        UnparsedPublicKey,
    };
    use jsonwebtoken::{DecodingKey, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TestClaims {
        sub: String,
        exp: i64,
    }

    #[test]
    fn test_algorithm_conversions() {
        use coset::iana::EnumI64 as _;

        for (alg, jose, cose_id) in [
            (SigningAlgorithm::Es256, "ES256", -7),
            (SigningAlgorithm::Es384, "ES384", -35),
            (SigningAlgorithm::EdDsa, "EdDSA", -8),
            (SigningAlgorithm::Rs256, "RS256", -257),
        ] {
            assert_eq!(alg.jose_name(), jose);
            assert_eq!(alg.cose_id(), cose_id);
            let jw_alg: jsonwebtoken::Algorithm = alg.into();
            let cose_alg: coset::iana::Algorithm = alg.into();
            assert_eq!(format!("{jw_alg:?}"), jose);
            assert_eq!(cose_alg.to_i64(), cose_id);
        }
    }

    #[test]
    fn test_es256_jwt_and_raw_signing() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::Es256);

        // JWT sign & verify using AsRef<EncodingKey>
        let header = Header::new(key.algorithm().into());
        let claims = TestClaims {
            sub: "test-subject".into(),
            exp: time::UtcDateTime::now().unix_timestamp() + 3600,
        };
        let token = encode(&header, &claims, key.as_ref()).unwrap();

        let decoding_key = DecodingKey::from_ec_der(key.public_key_bytes());
        let decoded = decode::<TestClaims>(
            &token,
            &decoding_key,
            &Validation::new(key.algorithm().into()),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);

        // Raw sign & verify
        let msg = b"status-list-cwt-payload";
        let sig = key.sign(msg).unwrap();
        assert_eq!(sig.len(), 64); // IEEE P1363 (R || S)

        let peer_pub = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key_bytes());
        peer_pub
            .verify(msg, &sig)
            .expect("raw signature verification failed");

        // Test From<SigningKey> consumes key
        let enc_key_owned: jsonwebtoken::EncodingKey = key.into();
        let token2 = encode(&header, &claims, &enc_key_owned).unwrap();
        assert!(!token2.is_empty());
    }

    #[test]
    fn test_es384_jwt_and_raw_signing() {
        let key = SigningKey::generate(SigningAlgorithm::Es384).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::Es384);

        // JWT sign & verify using AsRef<EncodingKey>
        let header = Header::new(key.algorithm().into());
        let claims = TestClaims {
            sub: "test-es384".into(),
            exp: 9999999999,
        };
        let token = encode(&header, &claims, key.as_ref()).unwrap();

        let decoding_key = DecodingKey::from_ec_der(key.public_key_bytes());
        let decoded = decode::<TestClaims>(
            &token,
            &decoding_key,
            &Validation::new(key.algorithm().into()),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);

        // Raw sign & verify
        let msg = b"status-list-cwt-payload-384";
        let sig = key.sign(msg).unwrap();
        assert_eq!(sig.len(), 96); // IEEE P1363 (R || S)

        let peer_pub = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key.public_key_bytes());
        peer_pub
            .verify(msg, &sig)
            .expect("raw signature verification failed");
    }

    #[test]
    fn test_eddsa_jwt_and_raw_signing() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::EdDsa);

        // JWT sign & verify using AsRef<EncodingKey>
        let header = Header::new(key.algorithm().into());
        let claims = TestClaims {
            sub: "test-eddsa".into(),
            exp: 9999999999,
        };
        let token = encode(&header, &claims, key.as_ref()).unwrap();

        let decoding_key = DecodingKey::from_ed_der(key.public_key_bytes());
        let decoded = decode::<TestClaims>(
            &token,
            &decoding_key,
            &Validation::new(key.algorithm().into()),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);

        // Raw sign & verify
        let msg = b"status-list-cwt-payload-ed25519";
        let sig = key.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);

        let peer_pub = UnparsedPublicKey::new(&ED25519, key.public_key_bytes());
        peer_pub
            .verify(msg, &sig)
            .expect("raw signature verification failed");
    }

    #[test]
    fn test_rs256_jwt_and_raw_signing() {
        let pem_str = include_str!("../../test_data/gcloud_test_key.dummy.pem");
        let key = SigningKey::from_pem(pem_str).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::Rs256);

        // JWT sign & verify using AsRef<EncodingKey>
        let header = Header::new(key.algorithm().into());
        let claims = TestClaims {
            sub: "test-rs256".into(),
            exp: 9999999999,
        };
        let token = encode(&header, &claims, key.as_ref()).unwrap();

        let decoding_key = DecodingKey::from_rsa_der(key.public_key_bytes());
        let decoded = decode::<TestClaims>(
            &token,
            &decoding_key,
            &Validation::new(key.algorithm().into()),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);

        // Raw sign & verify
        let msg = b"status-list-cwt-payload-rsa";
        let sig = key.sign(msg).unwrap();
        assert_eq!(sig.len(), 256); // 2048 bits = 256 bytes

        let peer_pub = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key_bytes());
        peer_pub
            .verify(msg, &sig)
            .expect("raw signature verification failed");
    }

    #[test]
    fn test_pem_roundtrip() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).unwrap();
        let pem_str = key.to_pkcs8_pem().unwrap();
        assert!(pem_str.starts_with("-----BEGIN PRIVATE KEY-----"));

        let loaded = SigningKey::from_pem(&pem_str).unwrap();
        assert_eq!(loaded.algorithm(), SigningAlgorithm::Es256);
        assert_eq!(loaded.public_key_bytes().len(), 65);
    }
}
