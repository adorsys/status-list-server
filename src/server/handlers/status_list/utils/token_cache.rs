use sha2::{Digest, Sha256};

use crate::domain::ports::SigningMaterial;

/// A stable digest of the exact signing material (private key PEM and the
/// certificate chain) that produced a token's signature.
///
/// Every provider serves `SigningMaterial` from an in-memory atomic snapshot that
/// is swapped atomically on rotation/renewal, so computing this on the hot path is
/// a cheap in-memory hash, not a key-load or network call. It changes whenever the
/// key or its certificate changes, which is what makes the signed-bytes cache
/// self-invalidating on rotation.
pub(crate) fn signer_fingerprint(material: &SigningMaterial) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.signing_key.algorithm().to_string().as_bytes());
    hasher.update(material.signing_key.public_key_bytes());
    if let Some(chain) = material.certificate_chain() {
        for part in chain {
            hasher.update(part.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn signer_fingerprint_changes_when_material_changes() {
        let key_a: Arc<dyn crate::domain::ports::TokenSigner> = Arc::new(
            crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .unwrap(),
        );
        let key_b: Arc<dyn crate::domain::ports::TokenSigner> = Arc::new(
            crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .unwrap(),
        );

        let material_a = SigningMaterial::new(
            Some(vec!["Y2VydC1h".to_string()]),
            Arc::clone(&key_a),
        )
        .unwrap();
        let material_b = SigningMaterial::new(
            Some(vec!["Y2VydC1h".to_string()]),
            Arc::clone(&key_b),
        )
        .unwrap();
        let material_c = SigningMaterial::new(None, Arc::clone(&key_a)).unwrap();

        let fp_a = signer_fingerprint(&material_a);
        let fp_b = signer_fingerprint(&material_b);
        let fp_c = signer_fingerprint(&material_c);
        assert_eq!(fp_a, signer_fingerprint(&material_a), "deterministic");
        assert_ne!(fp_a, fp_b, "key rotation must change the fingerprint");
        assert_ne!(fp_a, fp_c, "certificate change must change the fingerprint");
        assert_eq!(fp_a.len(), 64, "sha-256 hex digest");
    }
}
