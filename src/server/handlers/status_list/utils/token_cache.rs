use sha2::{Digest, Sha256};

use crate::domain::ports::SigningMaterial;

/// Changes on key or certificate rotation, which invalidates cached bytes and ETags.
/// Fields are length-prefixed so `["ab", "c"]` and `["abc"]` can't hash the same.
pub(crate) fn signer_fingerprint(material: &SigningMaterial) -> String {
    let mut hasher = Sha256::new();
    update_len_prefixed(
        &mut hasher,
        material.signing_key.algorithm().to_string().as_bytes(),
    );
    update_len_prefixed(&mut hasher, material.signing_key.public_key_bytes());
    match material.certificate_chain() {
        None => {
            hasher.update([0u8]);
        }
        Some(chain) => {
            hasher.update([1u8]);
            update_len_prefixed(&mut hasher, &(chain.len() as u64).to_le_bytes());
            for part in chain {
                update_len_prefixed(&mut hasher, part.as_bytes());
            }
        }
    }
    hex::encode(hasher.finalize())
}

fn update_len_prefixed(hasher: &mut Sha256, component: &[u8]) {
    hasher.update((component.len() as u64).to_le_bytes());
    hasher.update(component);
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

        let material_a =
            SigningMaterial::new(Some(vec!["Y2VydC1h".to_string()]), Arc::clone(&key_a)).unwrap();
        let material_b =
            SigningMaterial::new(Some(vec!["Y2VydC1h".to_string()]), Arc::clone(&key_b)).unwrap();
        let material_c = SigningMaterial::new(None, Arc::clone(&key_a)).unwrap();

        let fp_a = signer_fingerprint(&material_a);
        let fp_b = signer_fingerprint(&material_b);
        let fp_c = signer_fingerprint(&material_c);
        assert_eq!(fp_a, signer_fingerprint(&material_a), "deterministic");
        assert_ne!(fp_a, fp_b, "key rotation must change the fingerprint");
        assert_ne!(fp_a, fp_c, "certificate change must change the fingerprint");
        assert_eq!(fp_a.len(), 64, "sha-256 hex digest");
    }

    #[test]
    fn signer_fingerprint_frames_chain_boundaries_unambiguously() {
        let key: Arc<dyn crate::domain::ports::TokenSigner> = Arc::new(
            crate::utils::crypto::SigningKey::generate(
                crate::domain::models::token::SigningAlgorithm::Es256,
            )
            .unwrap(),
        );

        let split = SigningMaterial::new(
            Some(vec!["YWJj".to_string(), "ZGVm".to_string()]),
            Arc::clone(&key),
        )
        .unwrap();
        let joined =
            SigningMaterial::new(Some(vec!["YWJjZGVm".to_string()]), Arc::clone(&key)).unwrap();

        let fp_split = signer_fingerprint(&split);
        let fp_joined = signer_fingerprint(&joined);
        assert_ne!(
            fp_split, fp_joined,
            "structurally different chains that share a concatenated byte stream \
             must not collide in the signer fingerprint"
        );
    }
}
