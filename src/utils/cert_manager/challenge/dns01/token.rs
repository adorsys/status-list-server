#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
use std::{
    future::Future,
    time::{Duration, Instant},
};

#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
use secrecy::SecretString;
#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
use tokio::sync::Mutex;

#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
use crate::cert_manager::challenge::ChallengeError;

/// Cache for short-lived OAuth2 access tokens.
///
/// The lock is held across minting so concurrent callers wait for the
/// in-flight mint instead of minting duplicate tokens.
#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
pub(crate) struct TokenCache {
    inner: Mutex<Option<CachedToken>>,
}

#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
struct CachedToken {
    token: SecretString,
    expires_at: Instant,
}

#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
impl TokenCache {
    // Refresh tokens slightly before they expire
    const EXPIRY_SKEW: Duration = Duration::from_secs(60);

    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Return the cached token, or mint a new one when absent or expired
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
#[cfg(any(feature = "dns-azure", feature = "dns-gcloud"))]
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
                    Ok(("token".into(), std::time::Duration::from_secs(3600)))
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
            // A TTL below the expiry skew is expired immediately
            cache
                .get_or_mint(|| async {
                    mints.fetch_add(1, Ordering::SeqCst);
                    Ok(("token".into(), std::time::Duration::from_secs(30)))
                })
                .await
                .unwrap();
        }
        assert_eq!(mints.load(Ordering::SeqCst), 2);
    }
}
