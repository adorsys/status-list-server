use moka::future::Cache as MokaCache;
use std::time::Duration;

use crate::models::StatusListToken;

#[derive(Clone)]
pub struct Cache {
    pub status_list_token_cache: MokaCache<String, StatusListToken>,
}

impl Cache {
    pub fn new(ttl: u64, max_capacity: u64) -> Self {
        Self {
            status_list_token_cache: MokaCache::builder()
                .time_to_live(Duration::from_secs(ttl))
                .max_capacity(max_capacity)
                .build(),
        }
    }
}
