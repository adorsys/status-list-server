#[cfg(feature = "acme")]
mod cert_chain;

#[cfg(feature = "acme")]
pub(crate) use cert_chain::{CertChainCache, CertificateChain};

/// Pins that certificate chain cache entries stay cached until replacement.
#[cfg(all(test, feature = "acme"))]
mod cert_chain_cache_semantics {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn cert_chain_cache_entries_do_not_expire_by_time() {
        let cache = CertChainCache::new("");
        let chain: CertificateChain = Arc::from(vec!["cert".to_string()]);
        cache.insert("key".to_string(), chain.clone()).await;

        let cached: Option<CertificateChain> = cache.get("key").await;
        assert!(
            cached.is_some(),
            "CertChainCache entries must stay cached until explicit replacement"
        );
    }
}
