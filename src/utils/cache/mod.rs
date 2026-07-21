mod cert_chain;

pub(crate) use cert_chain::{CertChainCache, CertificateChain};

/// Pins the deliberately-opposite `ttl = 0` semantics of the two caches.
///
/// `CertChainCache` treats zero as "never expire"; the status-list cache treats
/// zero as "disabled". The status-list half of this matrix now lives with its
/// implementation in [`crate::adapters::cache`], since that cache sits behind
/// the [`StatusListCache`](crate::ports::StatusListCache) port.
#[cfg(test)]
mod ttl_zero_semantics_matrix {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn cert_chain_cache_zero_ttl_caches_indefinitely() {
        let cache = CertChainCache::new(Duration::ZERO, "");
        let chain: CertificateChain = Arc::from(vec!["cert".to_string()]);
        cache.insert("key".to_string(), chain.clone()).await;

        let cached: Option<CertificateChain> = cache.get("key").await;
        assert!(
            cached.is_some(),
            "CertChainCache with ttl=0: entries must cache indefinitely (never expire)"
        );
    }
}
