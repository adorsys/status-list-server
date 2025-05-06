use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use rand::{rngs::OsRng, TryRngCore};

use super::errors::Error;

const SECRET_KEY_LENGTH: usize = 32;

/// A keypair for signing and verifying JWT
#[derive(Debug, Clone)]
pub struct Keypair {
    repr: KeyRepr,
}

#[derive(Debug, Clone)]
struct KeyRepr {
    key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        const MAX_ATTEMPTS: u8 = 3;
        // Try up to 3 times to generate a random seed as a safeguard against bad RNG
        for attempt in 0..MAX_ATTEMPTS {
            match OsRng.try_fill_bytes(&mut seed) {
                Ok(()) => break,
                Err(err) => {
                    if attempt == MAX_ATTEMPTS - 1 {
                        tracing::error!("Failed to generate random bytes: {err:?}");
                        return Err(Error::KeyGenFailed);
                    }
                }
            }
        }
        let key = SigningKey::from_slice(&seed).map_err(|err| {
            tracing::error!("Failed to create signing key: {err:?}");
            Error::KeyGenFailed
        })?;

        let keypair = Keypair {
            repr: KeyRepr { key },
        };
        Ok(keypair)
    }

    /// Get the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.repr.key
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.repr.key.verifying_key()
    }

    /// Create a keypair from a pkcs8 PEM file
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|err| {
            tracing::error!("Failed to create signing key from PEM: {err:?}");
            Error::KeyGenFailed
        })?;
        Ok(Keypair {
            repr: KeyRepr { key },
        })
    }

    /// Convert the private key to a pkcs8 PEM string
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        self.repr
            .key
            .to_pkcs8_pem(LineEnding::default())
            .map_err(|err| {
                tracing::error!("Failed to convert signing key to PEM: {err:?}");
                Error::PemGenFailed
            })
            .map(|pem| pem.to_string())
    }

    /// Convert the private key to a pkcs8 PEM bytes
    pub fn to_pkcs8_pem_bytes(&self) -> Result<Vec<u8>, Error> {
        self.to_pkcs8_pem().map(|pem| pem.into_bytes())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use p256::pkcs8::EncodePublicKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_validate_generated_signing_key() {
        #[derive(Debug, serde::Deserialize, serde::Serialize)]
        struct Claims {
            exp: usize,
        }

        let keypair = Keypair::generate().unwrap();

        let header = Header {
            alg: jsonwebtoken::Algorithm::ES256,
            ..Default::default()
        };

        let encoding_key =
            EncodingKey::from_ec_pem(&keypair.to_pkcs8_pem_bytes().unwrap()).unwrap();

        let exp_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 3600;

        let claims = Claims { exp: exp_time };
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let public_key_pem = keypair
            .repr
            .key
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes()).unwrap();

        let decoded = decode::<Claims>(
            &token,
            &decoding_key,
            &Validation::new(jsonwebtoken::Algorithm::ES256),
        );

        assert!(decoded.is_ok(), "Decoding failed: {:?}", decoded.err());
    }
}