use rsa::{RsaPrivateKey, RsaPublicKey};

use super::errors::Error;

pub struct Keypair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

/// This function should be called once to generate a new keypair
pub fn keygen() -> Result<Keypair, Error> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|_| Error::Generic("failed to generate key".to_string()))?;
    let pub_key = RsaPublicKey::from(&priv_key);

    let keypair = Keypair {
        private_key: priv_key,
        public_key: pub_key,
    };
    Ok(keypair)
}

#[cfg(test)]
mod test {
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::utils::keygen::keygen;

    #[test]
    fn test() {
        #[derive(Debug, serde::Deserialize, serde::Serialize)]
        struct Claims {
            exp: usize,
        }

        let keypair = keygen().unwrap();

        let header = Header {
            alg: jsonwebtoken::Algorithm::RS256,
            ..Default::default()
        };

        let encoding_key = EncodingKey::from_rsa_pem(
            keypair
                .private_key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::CRLF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        let exp_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 3600;

        let claims = Claims { exp: exp_time };
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let public_key_pem = keypair
            .public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::CRLF)
            .unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).unwrap();

        let decoded = decode::<Claims>(
            &token,
            &decoding_key,
            &Validation::new(jsonwebtoken::Algorithm::RS256),
        );

        assert!(decoded.is_ok(), "Decoding failed: {:?}", decoded.err());
    }
}
