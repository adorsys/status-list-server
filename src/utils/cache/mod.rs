mod cert_chain;
mod status_list;

pub(crate) use cert_chain::{CertChainCache, CertificateChain};
pub(crate) use status_list::StatusListCache;

#[cfg(test)]
mod ttl_zero_semantics_matrix {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn sample_status_record(id: &str) -> crate::models::StatusListRecord {
        crate::models::StatusListRecord {
            list_id: id.to_string(),
            issuer: "issuer".to_string(),
            sub: "sub".to_string(),
            status_list: crate::models::StatusList {
                bits: 1,
                lst: "test".to_string(),
            },
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn cert_chain_cache_zero_ttl_caches_indefinitely() {
        use crate::utils::cache::CertChainCache;
        let cache = CertChainCache::new(Duration::ZERO, "");
        let chain: CertificateChain = Arc::from(vec!["cert".to_string()]);
        cache.insert("key".to_string(), chain.clone()).await;

        let cached: Option<CertificateChain> = cache.get("key").await;
        assert!(
            cached.is_some(),
            "CertChainCache with ttl=0: entries must cache indefinitely (never expire)"
        );
    }

    #[tokio::test]
    async fn status_list_cache_zero_ttl_disables_cache() {
        use crate::utils::cache::StatusListCache;
        let cache = StatusListCache::new(0, 10);
        cache
            .insert("list-1".to_string(), sample_status_record("list-1"))
            .await;

        let cached = cache.get("list-1").await;
        assert!(
            cached.is_none(),
            "StatusListCache with ttl=0: entries must expire immediately (cache disabled)"
        );
    }
}
