use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey},
    SigningKey, VerifyingKey, SECRET_KEY_LENGTH,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::errors::Error;

/// A keypair for signing and verifying JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair {
    repr: KeyRepr,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyRepr {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| Error::KeyGenFailed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let keypair = Keypair {
            repr: KeyRepr {
                signing_key,
                verifying_key,
            },
        };
        Ok(keypair)
    }

    /// Convert the private key to a pkcs8 PEM string
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        self.repr
            .signing_key
            .to_pkcs8_pem(LineEnding::default())
            .map_err(|_| Error::PemGenFailed)
            .map(|pem| pem.to_string())
    }

    /// Convert the private key to a pkcs8 PEM bytes
    pub fn to_pkcs8_pem_bytes(&self) -> Result<Vec<u8>, Error> {
        self.to_pkcs8_pem().map(|pem| pem.into_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test() {
        #[derive(Debug, serde::Deserialize, serde::Serialize)]
        struct Claims {
            exp: usize,
        }

        let keypair = Keypair::generate().unwrap();

        let header = Header {
            alg: jsonwebtoken::Algorithm::EdDSA,
            ..Default::default()
        };

        let encoding_key =
            EncodingKey::from_ed_pem(&keypair.to_pkcs8_pem_bytes().unwrap()).unwrap();

        let exp_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 3600;

        let claims = Claims { exp: exp_time };
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let public_key_pem = keypair
            .repr
            .verifying_key
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem.as_bytes()).unwrap();

        let decoded = decode::<Claims>(
            &token,
            &decoding_key,
            &Validation::new(jsonwebtoken::Algorithm::EdDSA),
        );

        assert!(decoded.is_ok(), "Decoding failed: {:?}", decoded.err());
    }
}
