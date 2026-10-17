use std::{
    future::Future,
    time::{Duration, Instant},
};

use secrecy::SecretString;
use tokio::sync::Mutex;

use crate::cert_manager::challenge::ChallengeError;

/// Holds the lock while minting so concurrent callers share one token.
pub(crate) struct TokenCache {
    inner: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: SecretString,
    expires_at: Instant,
}

impl TokenCache {
    const EXPIRY_SKEW: Duration = Duration::from_secs(60);

    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub(crate) async fn get_or_mint<F, Fut>(&self, mint: F) -> Result<SecretString, ChallengeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(SecretString, Duration), ChallengeError>>,
    {
        let mut guard = self.inner.lock().await;
        if let Some(cached) = guard.as_ref()
            && Instant::now() < cached.expires_at
        {
            return Ok(cached.token.clone());
        }

        let (token, ttl) = mint().await?;
        *guard = Some(CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + ttl.saturating_sub(Self::EXPIRY_SKEW),
        });
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn mints_once_while_token_is_valid() {
        let cache = TokenCache::new();
        let mints = AtomicU32::new(0);

        for _ in 0..3 {
            let token = cache
                .get_or_mint(|| async {
                    mints.fetch_add(1, Ordering::SeqCst);
                    Ok(("token".into(), Duration::from_secs(3600)))
                })
                .await
                .unwrap();
            assert_eq!(token.expose_secret(), "token");
        }
        assert_eq!(mints.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mints_again_when_token_expired() {
        let cache = TokenCache::new();
        let mints = AtomicU32::new(0);

        for _ in 0..2 {
            cache
                .get_or_mint(|| async {
                    mints.fetch_add(1, Ordering::SeqCst);
                    Ok(("token".into(), Duration::from_secs(30)))
                })
                .await
                .unwrap();
        }
        assert_eq!(mints.load(Ordering::SeqCst), 2);
    }
}
