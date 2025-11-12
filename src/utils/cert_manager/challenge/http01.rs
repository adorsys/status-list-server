use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::HeaderValue,
    response::IntoResponse,
    routing::get,
    Router,
};
use color_eyre::eyre::eyre;
use hyper::{header, StatusCode};
use instant_acme::{AuthorizationHandle, ChallengeType};
use tokio::{
    net::TcpListener,
    sync::{
        oneshot::{self, Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use tracing::{error, info, warn};

use crate::cert_manager::{
    challenge::{ChallengeError, ChallengeHandler, CleanupFuture},
    storage::Storage,
};

type ServerHandler = Arc<RwLock<Option<(JoinHandle<()>, Sender<()>)>>>;

/// Struct representing the HTTP01 challenge handler
pub struct Http01Handler {
    challenge_storage: Arc<dyn Storage>,
    host: String,
    port: u16,
    server_handle: ServerHandler,
}

impl Http01Handler {
    /// Create a new instance of the HTTP-01 challenge handler
    pub fn new(challenge_storage: impl Storage + 'static, host: &str, port: u16) -> Self {
        Self {
            challenge_storage: Arc::new(challenge_storage),
            host: host.into(),
            port,
            server_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the server and return a receiver to confirm readiness
    async fn start_server(&self) -> Result<Receiver<()>, ChallengeError> {
        let (ready_tx, ready_rx) = oneshot::channel();

        // Check if server is already running
        if self.server_handle.read().await.is_some() {
            info!("HTTP-01 challenge server already running");
            ready_tx.send(()).unwrap();
            return Ok(ready_rx);
        }

        let app = Router::new()
            .route("/.well-known/acme-challenge/{token}", get(serve_challenge))
            .with_state(self.challenge_storage.clone());

        // ACME uses port 80 for HTTP-01 challenges
        let listener = TcpListener::bind(format!("{}:{}", self.host, self.port)).await?;
        info!("Starting HTTP-01 challenge server on port {}...", self.port);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            });
            ready_tx.send(()).unwrap();
            if let Err(e) = server.await {
                warn!("HTTP-01 server error: {e}");
            }
        });

        self.server_handle
            .write()
            .await
            .replace((handle, shutdown_tx));
        Ok(ready_rx)
    }
}

async fn serve_challenge(
    Path(token): Path<String>,
    State(challenge_store): State<Arc<dyn Storage>>,
) -> Result<impl IntoResponse, StatusCode> {
    match challenge_store.load(&token).await {
        Ok(Some(challenge)) => {
            info!("Serving ACME challenge for token: {token}");
            Ok((
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                )],
                challenge,
            ))
        }
        Ok(None) => {
            warn!("Challenge not found for token: {token}");
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Error while retrieving challenge for token {token}: {e:?}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[async_trait]
impl ChallengeHandler for Http01Handler {
    async fn handle_authorization<'a>(
        &'a self,
        authz: &'a mut AuthorizationHandle<'a>,
    ) -> Result<CleanupFuture, ChallengeError> {
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| ChallengeError::Other(eyre!("No HTTP-01 challenge found")))?;

        let token = challenge.token.clone();
        let proof = challenge.key_authorization().as_str().to_string();

        // Start the server and wait for it to be ready
        self.start_server()
            .await?
            .await
            .map_err(|_| ChallengeError::Other(eyre!("HTTP-01 server failed to start")))?;

        // Store the key authorization
        self.challenge_storage.store(&token, &proof).await?;

        // Signal the server we are ready to respond to the challenge
        challenge.set_ready().await?;

        let cleanup = {
            let storage = self.challenge_storage.clone();
            let handle = self.server_handle.clone();
            async move {
                let (result, _) = tokio::join!(
                    async { storage.delete(&token).await.map_err(Into::into) },
                    async {
                        if let Some((_, shutdown_tx)) = handle.write().await.take() {
                            // Signal the server to shutdown
                            let _ = shutdown_tx.send(());
                        }
                    }
                );
                result
            }
        };
        Ok(CleanupFuture::new(cleanup))
    }
}
