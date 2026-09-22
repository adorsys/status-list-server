use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use der::{Decode, Encode};
use std::fmt;
use thiserror::Error;

use crate::domain::models::token::{SigningAlgorithm, TokenSignerError};
use crate::domain::ports::TokenSigner;

// Standard Cryptographic OIDs
const OID_ID_EC_PUBLIC_KEY: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ED25519: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_RSA_ENCRYPTION: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

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

/// Unified signing key supporting ECDSA (P-256, P-384), Ed25519, and RSA (RS256).
pub struct SigningKey {
    algorithm: SigningAlgorithm,
    inner: SigningKeyInner,
    public_key: Box<[u8]>,
}

struct SigningKeyInner {
    pair: KeyPairInner,
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

        let (pair, public_key) = match algorithm {
            SigningAlgorithm::Es256 => {
                let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)?;
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ecdsa(kp), pub_bytes.into())
            }
            SigningAlgorithm::Es384 => {
                let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, der)?;
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ecdsa(kp), pub_bytes.into())
            }
            SigningAlgorithm::EdDsa => {
                let kp = Ed25519KeyPair::from_pkcs8(der)?;
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Ed25519(kp), pub_bytes.into())
            }
            SigningAlgorithm::Rs256 => {
                let kp = RsaKeyPair::from_pkcs8(der)?;
                let pub_bytes = kp.public_key().as_ref().to_owned();
                (KeyPairInner::Rsa(kp), pub_bytes.into())
            }
        };

        Ok(Self {
            algorithm,
            inner: SigningKeyInner { pair, rng },
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

impl TokenSigner for SigningKey {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TokenSignerError> {
        self.sign(data)
            .map_err(|err| TokenSignerError::new(err.to_string()))
    }

    fn public_key_bytes(&self) -> &[u8] {
        self.public_key_bytes()
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

    #[test]
    fn test_algorithm_identifiers() {
        for (alg, jose, cose_id) in [
            (SigningAlgorithm::Es256, "ES256", -7),
            (SigningAlgorithm::Es384, "ES384", -35),
            (SigningAlgorithm::EdDsa, "EdDSA", -8),
            (SigningAlgorithm::Rs256, "RS256", -257),
        ] {
            assert_eq!(alg.jose_name(), jose);
            assert_eq!(alg.cose_id(), cose_id);
        }
    }

    #[test]
    fn signs_and_verifies_every_supported_algorithm() {
        let keys = [
            SigningKey::generate(SigningAlgorithm::Es256).unwrap(),
            SigningKey::generate(SigningAlgorithm::Es384).unwrap(),
            SigningKey::generate(SigningAlgorithm::EdDsa).unwrap(),
            SigningKey::from_pem(include_str!("../../test_data/gcloud_test_key.dummy.pem"))
                .unwrap(),
        ];

        for key in &keys {
            let message = b"status-list-token-signing-input";
            let signature = key.sign(message).unwrap();
            match key.algorithm() {
                SigningAlgorithm::Es256 => {
                    assert_eq!(signature.len(), 64);
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key_bytes())
                        .verify(message, &signature)
                        .expect("ES256 signature verifies");
                }
                SigningAlgorithm::Es384 => {
                    assert_eq!(signature.len(), 96);
                    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key.public_key_bytes())
                        .verify(message, &signature)
                        .expect("ES384 signature verifies");
                }
                SigningAlgorithm::EdDsa => {
                    assert_eq!(signature.len(), 64);
                    UnparsedPublicKey::new(&ED25519, key.public_key_bytes())
                        .verify(message, &signature)
                        .expect("Ed25519 signature verifies");
                }
                SigningAlgorithm::Rs256 => {
                    assert_eq!(signature.len(), 256);
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key_bytes())
                        .verify(message, &signature)
                        .expect("RS256 signature verifies");
                }
            }
        }
    }

    #[test]
    fn pkcs8_pem_roundtrips_every_supported_algorithm() {
        let keys = [
            SigningKey::generate(SigningAlgorithm::Es256).unwrap(),
            SigningKey::generate(SigningAlgorithm::Es384).unwrap(),
            SigningKey::generate(SigningAlgorithm::EdDsa).unwrap(),
            SigningKey::from_pem(include_str!("../../test_data/gcloud_test_key.dummy.pem"))
                .unwrap(),
        ];

        for key in keys {
            let pem = key.to_pkcs8_pem().unwrap();
            assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
            let loaded = SigningKey::from_pem(&pem).unwrap();
            assert_eq!(loaded.algorithm(), key.algorithm());
            assert_eq!(loaded.public_key_bytes(), key.public_key_bytes());
        }
    }

    #[test]
    fn accepts_sec1_ec_private_key_pem() {
        let pkcs8 = pem::parse(include_str!("../../test_data/ec-private.pem")).unwrap();
        let pki = pkcs8::PrivateKeyInfoRef::from_der(pkcs8.contents()).unwrap();
        let parsed_sec1 = sec1::EcPrivateKey::from_der(pki.private_key.as_bytes()).unwrap();
        let sec1_with_curve = sec1::EcPrivateKey {
            private_key: parsed_sec1.private_key,
            parameters: Some(sec1::EcParameters::NamedCurve(OID_SECP256R1)),
            public_key: parsed_sec1.public_key,
        }
        .to_der()
        .unwrap();
        let sec1 = pem::encode(&pem::Pem::new("EC PRIVATE KEY", sec1_with_curve));

        let key = SigningKey::from_pem(&sec1).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::Es256);
    }

    #[test]
    fn accepts_pkcs1_rsa_private_key_pem() {
        let pkcs8 = pem::parse(include_str!("../../test_data/gcloud_test_key.dummy.pem")).unwrap();
        let pki = pkcs8::PrivateKeyInfoRef::from_der(pkcs8.contents()).unwrap();
        let pkcs1 = pem::encode(&pem::Pem::new(
            "RSA PRIVATE KEY",
            pki.private_key.as_bytes(),
        ));

        let key = SigningKey::from_pem(&pkcs1).unwrap();
        assert_eq!(key.algorithm(), SigningAlgorithm::Rs256);
    }

    #[test]
    fn rejects_automatic_rs256_key_generation() {
        assert!(matches!(
            SigningKey::generate(SigningAlgorithm::Rs256),
            Err(Error::UnsupportedKeygen(algorithm)) if algorithm == "RS256"
        ));
    }
}
