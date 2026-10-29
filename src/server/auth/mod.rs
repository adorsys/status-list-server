//! Authentication middleware validating bearer JWTs against registered issuer credentials.

pub mod errors;
pub mod hosted;
pub mod hosted_service;
pub mod issuer_registry;

use axum::{
    body::Body,
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::{StatusCode, header};
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use crate::domain::models::credential::PublicJwk;
use crate::domain::models::credential::{Issuer, MANAGEMENT_SIGNING_ALGORITHMS};
use crate::domain::models::credential::{KeyResolveError, Principal};
use crate::server::{AppState, error::ApiError};

const JWT_REQUIRED_SPEC_CLAIMS: &[&str] = &["iss", "exp"];
const JWT_REQUIRED_SPEC_CLAIMS_WITH_AUDIENCE: &[&str] = &["iss", "exp", "aud"];
const MANAGEMENT_TOKEN_TYPE: &str = "statuslist-management+jwt";

/// Required management claims are non-optional (`iss`, `iat`, `exp`).
/// Optional claims are deserialized as `Option` and validated when present.
#[derive(Debug, Serialize, Deserialize)]
struct ManagementClaims {
    iss: String,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    exp: u64,
}

impl ManagementClaims {
    fn validate_policy(
        &self,
        now: u64,
        leeway_secs: u64,
        max_token_lifetime_secs: u64,
    ) -> Result<(), &'static str> {
        if self.exp <= self.iat {
            return Err("exp must be later than iat");
        }

        if self.iat > now.saturating_add(leeway_secs) {
            return Err("iat is in the future beyond configured leeway");
        }

        // exp > iat was established above, so unsigned subtraction is safe.
        let lifetime = self.exp - self.iat;
        if lifetime > max_token_lifetime_secs {
            return Err("token lifetime exceeds configured maximum");
        }

        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    iss: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    exp: u64,
}

/// Authenticated management principal derived from a validated issuer JWT.
///
/// Handlers should depend on this typed principal instead of extracting a raw
/// issuer string from request extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedIssuer {
    issuer: Issuer,
    aggregation_id: Option<crate::domain::models::credential::AggregationId>,
}

impl AuthenticatedIssuer {
    /// Build an authenticated issuer principal from a verified issuer identity.
    #[cfg(test)]
    pub(crate) fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            aggregation_id: None,
        }
    }

    /// Build a principal together with the immutable registry data resolved
    /// while authenticating the request.
    pub(crate) fn with_aggregation_id(
        issuer: Issuer,
        aggregation_id: crate::domain::models::credential::AggregationId,
    ) -> Self {
        Self {
            issuer,
            aggregation_id: Some(aggregation_id),
        }
    }

    pub(crate) fn aggregation_id(
        &self,
    ) -> Option<crate::domain::models::credential::AggregationId> {
        self.aggregation_id
    }

    /// Borrow the verified issuer identity associated with this principal.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Consume the principal and return the verified issuer identity.
    pub fn into_issuer(self) -> Issuer {
        self.issuer
    }
}

impl From<AuthenticatedIssuer> for Issuer {
    fn from(principal: AuthenticatedIssuer) -> Self {
        principal.issuer
    }
}

impl AsRef<Issuer> for AuthenticatedIssuer {
    fn as_ref(&self) -> &Issuer {
        self.issuer()
    }
}

impl AsRef<str> for AuthenticatedIssuer {
    fn as_ref(&self) -> &str {
        &self.issuer.0
    }
}

impl<S> FromRequestParts<S> for AuthenticatedIssuer
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let principal = parts.extensions.get::<AuthenticatedIssuer>().cloned();
        async move {
            principal.ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "missing_auth_context",
                    Some("Authenticated issuer context is missing".into()),
                )
            })
        }
    }
}

/// Formats the underlying issuer identifier, preserving the canonical string
/// representation used by tracing fields.
impl std::fmt::Display for AuthenticatedIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.issuer.0.fmt(f)
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedAdmin {
    pub id: String,
}

#[derive(Clone)]
struct AdminAuthRequest;

/// Only a registry admin with `issuers:write` may change hosted lifecycle state.
pub async fn admin_auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    request.extensions_mut().insert(AdminAuthRequest);
    auth(State(state), request, next).await
}

/// Authentication middleware acting as a safeguard for unauthorized issuers
pub async fn auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some(auth_header) = auth_header else {
        crate::utils::metrics::record_management_auth_request(None, None, "missing_token");
        return Err(AuthenticationError::MissingToken);
    };
    let Some((scheme, token)) = auth_header.split_once(char::is_whitespace) else {
        if auth_header.eq_ignore_ascii_case("Bearer") {
            return Err(invalid_auth(None, None, "empty Bearer token"));
        }
        crate::utils::metrics::record_management_auth_request(None, None, "missing_token");
        return Err(AuthenticationError::MissingToken);
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        crate::utils::metrics::record_management_auth_request(None, None, "missing_token");
        return Err(AuthenticationError::MissingToken);
    }
    if token.trim().is_empty() {
        return Err(invalid_auth(None, None, "empty Bearer token"));
    }

    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| invalid_auth(None, None, format!("invalid JWT header: {e}")))?;
    let typ_ok = header.typ.as_deref().is_some_and(|typ| {
        typ.eq_ignore_ascii_case(MANAGEMENT_TOKEN_TYPE)
            || typ.get(.."application/".len()).is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case("application/")
                    && typ
                        .get("application/".len()..)
                        .is_some_and(|value| value.eq_ignore_ascii_case(MANAGEMENT_TOKEN_TYPE))
            })
    });
    let Some(kid) = header.kid.clone() else {
        return Err(invalid_auth(None, None, "missing kid"));
    };
    if kid.is_empty() || kid.chars().count() > 255 {
        return Err(invalid_auth(Some(&kid), None, "invalid kid length"));
    }
    if !typ_ok {
        return Err(invalid_auth(Some(&kid), None, "missing or invalid typ"));
    }
    if header.crit.is_some() {
        return Err(invalid_auth(
            Some(&kid),
            None,
            "crit header is not permitted",
        ));
    }
    let allowed_algorithm = MANAGEMENT_SIGNING_ALGORITHMS.contains(&header.alg);
    if !allowed_algorithm {
        return Err(invalid_auth(Some(&kid), None, "algorithm is not allowed"));
    }

    let resolved = match state.issuer_key_resolver.resolve(&kid).await {
        Err(KeyResolveError::BackendUnavailable) => {
            // The header `kid` is unauthenticated here, so it is not used as a
            // label; only the retryable outcome is recorded.
            crate::utils::metrics::record_management_auth_request(
                None,
                None,
                "backend_unavailable",
            );
            tracing::warn!(
                kid = %bounded_identifier(Some(&kid)),
                "management JWT rejected: the trust backend is unavailable"
            );
            return Err(AuthenticationError::BackendUnavailable);
        }
        result => result.map_err(|reason| invalid_auth(Some(&kid), None, reason))?,
    };
    let admin_request = request.extensions().get::<AdminAuthRequest>().is_some();
    let (registered_issuer, registered_aggregation_id) = match &resolved.principal {
        Principal::Issuer { id, aggregation_id } if !admin_request => {
            (id.as_str(), Some(*aggregation_id))
        }
        Principal::Admin { id, scopes }
            if admin_request && scopes.iter().any(|scope| scope == "issuers:write") =>
        {
            (id.as_str(), None)
        }
        Principal::Admin { id, .. } => {
            return Err(invalid_auth(
                Some(&kid),
                Some(id),
                "admin scope is insufficient",
            ));
        }
        Principal::Issuer { id, .. } => {
            return Err(invalid_auth(
                Some(&kid),
                Some(id),
                "issuer keys cannot authenticate admin requests",
            ));
        }
    };
    let registered_kid = resolved.public_key.key_id();
    let registered_alg = resolved.public_key.algorithm();
    if registered_kid != kid || registered_alg != header.alg {
        return Err(invalid_auth(
            Some(&kid),
            Some(registered_issuer),
            "algorithm or key id mismatch",
        ));
    }

    let decoding_key = DecodingKey::from_jwk(resolved.public_key.jwk()).map_err(|e| {
        invalid_auth(
            Some(&kid),
            Some(registered_issuer),
            format!("invalid verification key: {e}"),
        )
    })?;

    let mut validation = Validation::new(registered_alg);
    validation.leeway = state.management_auth.leeway_secs;
    validation.validate_nbf = true;
    validation.set_issuer(&[registered_issuer]);
    if !state.management_auth.audiences.is_empty() {
        validation.set_required_spec_claims(JWT_REQUIRED_SPEC_CLAIMS_WITH_AUDIENCE);
        validation.set_audience(&state.management_auth.audiences);
    } else {
        // jsonwebtoken can require registered claims like `iss` and `exp`;
        // `iat` is required by deserializing into `ManagementClaims`.
        validation.set_required_spec_claims(JWT_REQUIRED_SPEC_CLAIMS);
        validation.validate_aud = false;
    }

    let token_data = jsonwebtoken::decode::<ManagementClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            invalid_auth(
                Some(&kid),
                Some(registered_issuer),
                format!("claim or signature validation failed: {e}"),
            )
        })?;
    let now = current_unix_timestamp()?;
    token_data
        .claims
        .validate_policy(
            now,
            state.management_auth.leeway_secs,
            state.management_auth.max_token_lifetime_secs,
        )
        .map_err(|reason| invalid_auth(Some(&kid), Some(registered_issuer), reason))?;

    if let Some(aggregation_id) = registered_aggregation_id {
        request
            .extensions_mut()
            .insert(AuthenticatedIssuer::with_aggregation_id(
                Issuer(registered_issuer.to_owned()),
                aggregation_id,
            ));
    } else {
        request.extensions_mut().insert(AuthenticatedAdmin {
            id: registered_issuer.to_owned(),
        });
    }
    let metric_issuer = bounded_identifier(Some(registered_issuer));
    let metric_kid = bounded_identifier(Some(&kid));
    crate::utils::metrics::record_management_auth_request(
        Some(&metric_issuer),
        Some(&metric_kid),
        "success",
    );
    Ok(next.run(request).await)
}

fn invalid_auth(
    kid: Option<&str>,
    iss: Option<&str>,
    reason: impl std::fmt::Display,
) -> AuthenticationError {
    let metric_issuer = bounded_identifier(iss);
    crate::utils::metrics::record_management_auth_request(Some(&metric_issuer), None, "rejected");
    tracing::warn!(kid = %bounded_identifier(kid), iss = %bounded_identifier(iss), reason = %reason, "Management JWT rejected");
    AuthenticationError::InvalidToken
}

fn bounded_identifier(value: Option<&str>) -> String {
    value.unwrap_or("-").chars().take(255).collect()
}

fn current_unix_timestamp() -> Result<u64, AuthenticationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthenticationError::InternalServer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{metrics_after, test_app_state};
    use crate::utils::file_watcher::FileWatcher;
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        extract::Request,
        http::{StatusCode, header},
        routing::{get, put},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Notify;
    use tokio::time::{sleep, timeout};
    use tower::ServiceExt;

    #[derive(Default)]
    struct RequestGate {
        entered: Notify,
        release: Notify,
    }

    async fn gated_test_handler(Extension(gate): Extension<Arc<RequestGate>>) -> &'static str {
        gate.entered.notify_one();
        gate.release.notified().await;
        "Ok"
    }

    async fn gated_credentials_handler(
        State(state): State<AppState>,
        issuer: AuthenticatedIssuer,
        Extension(gate): Extension<Arc<RequestGate>>,
    ) -> Result<axum::Json<crate::server::handlers::issue_credential::RegistrationResponse>, ApiError>
    {
        gate.entered.notify_one();
        gate.release.notified().await;
        crate::server::handlers::issue_credential::get_credential(State(state), issuer).await
    }

    fn create_gated_test_router(app_state: AppState, gate: Arc<RequestGate>) -> Router {
        Router::new()
            .route("/test", get(gated_test_handler))
            .layer(Extension(gate))
            .layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth,
            ))
            .with_state(app_state)
    }

    fn create_gated_credentials_router(app_state: AppState, gate: Arc<RequestGate>) -> Router {
        Router::new()
            .route("/credentials", get(gated_credentials_handler))
            .layer(Extension(gate))
            .layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth,
            ))
            .with_state(app_state)
    }

    fn create_test_router(app_state: AppState) -> Router {
        async fn test_handler() -> &'static str {
            "Ok"
        }
        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth,
            ))
            .with_state(app_state)
    }

    fn test_ec_private_pem() -> String {
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----".to_string()
    }

    fn test_public_jwk() -> crate::domain::models::credential::PublicJwk {
        crate::domain::models::credential::PublicJwk::try_new(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-key",
                "alg": "ES256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#
            .as_bytes()
            .to_vec(),
        )
        .unwrap()
    }

    fn rotation_private_pem() -> String {
        "-----BEGIN PRIVATE KEY-----\nMIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB\nAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA\n///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV\nAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg\n9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A\nAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgyO8dO/IXvyo2\nloV5QPB42Gv31v5U5pik40FfQ12VVzWhRANCAASozvoFuoPcmZaeJPgC5JgzkrDE\nLlYA1w9cGkJRB8B/UXP3TuiR9gairPTOlLAzTEO0bGDIMKjjeU4tfYCm/Jy5\n-----END PRIVATE KEY-----".to_string()
    }

    fn rotation_public_jwk() -> PublicJwk {
        PublicJwk::try_new(
            br#"{
                "kty":"EC", "crv":"P-256", "kid":"rotation-key", "alg":"ES256",
                "x":"qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E",
                "y":"c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"
            }"#
            .to_vec(),
        )
        .unwrap()
    }

    fn now() -> u64 {
        current_unix_timestamp().unwrap()
    }

    #[test]
    fn rejection_logs_bound_identifiers_and_include_registered_owner() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct LogWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for LogWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || LogWriter(sink.clone()))
            .finish();
        let long = "é".repeat(1000);
        tracing::subscriber::with_default(subscriber, || {
            invalid_auth(Some(&long), Some("registered-owner"), "bad signature");
        });
        let text = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(text.contains("registered-owner"));
        assert!(text.contains(&"é".repeat(255)));
        assert!(!text.contains(&"é".repeat(256)));
        assert_eq!(bounded_identifier(Some(&long)).chars().count(), 255);
    }

    fn create_test_token(issuer: &str, secret: &EncodingKey, alg: Algorithm) -> String {
        let now = now();

        let claims = TestClaims {
            iss: issuer.to_string(),
            iat: now,
            nbf: None,
            exp: now + 300,
        };

        let mut header = Header::new(alg);
        header.typ = Some("statuslist-management+jwt".to_string());
        header.kid = Some("test-key".to_string());
        encode(&header, &claims, secret).unwrap()
    }

    fn sign_claims(claims: serde_json::Value, secret: &EncodingKey) -> String {
        sign_claims_with_header(claims, secret, management_header())
    }

    fn management_header() -> Header {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("statuslist-management+jwt".to_string());
        header.kid = Some("test-key".to_string());
        header
    }

    fn sign_claims_with_header(
        claims: serde_json::Value,
        secret: &EncodingKey,
        header: Header,
    ) -> String {
        encode(&header, &claims, secret).unwrap()
    }

    async fn test_state_with_registered_issuer() -> AppState {
        let mut state = test_app_state(None).await;
        let public_key = test_public_jwk();
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: public_key.clone(),
            })
            .await
            .unwrap();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "test-issuer",
                "aggregation_id": uuid::Uuid::new_v4(),
                "keys": [{
                    "kid": public_key.key_id(),
                    "alg": format!("{:?}", public_key.algorithm()),
                    "jwk": public_key.jwk(),
                }]
            }],
            "admins": []
        }))
        .unwrap();
        state.set_issuer_registry(Arc::new(
            issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));
        state
    }

    #[tokio::test]
    async fn startup_reconciliation_applies_revocation_without_a_second_file_change() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("issuers.yaml");
        let public_key = test_public_jwk();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "test-issuer",
                "aggregation_id": uuid::Uuid::new_v4(),
                "keys": [{
                    "kid": public_key.key_id(),
                    "alg": "ES256",
                    "jwk": public_key.jwk(),
                }],
            }],
            "admins": []
        }))
        .unwrap();
        std::fs::write(&file, registry).unwrap();
        let handle = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
        let state = test_app_state(None).await;

        crate::setup::spawn_issuer_registry_watcher(
            handle.clone(),
            state.service,
            None,
            file.clone(),
            Duration::from_secs(1),
        );
        std::fs::write(&file, "version: 1\nissuers: []\nadmins: []\n").unwrap();

        timeout(Duration::from_secs(3), async {
            loop {
                if handle.resolve("test-key").is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("startup reconciliation did not apply revocation");
    }

    #[tokio::test]
    async fn gated_credentials_request_uses_the_authenticated_registry_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("issuers.yaml");
        let aggregation_id = uuid::Uuid::new_v4();
        let public_key = test_public_jwk();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "test-issuer",
                "aggregation_id": aggregation_id,
                "keys": [{
                    "kid": public_key.key_id(),
                    "alg": "ES256",
                    "jwk": public_key.jwk(),
                }],
            }],
            "admins": []
        }))
        .unwrap();
        std::fs::write(&file, registry).unwrap();

        let mut state = test_app_state(None).await;
        let registry_handle = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
        state.set_issuer_registry(registry_handle.clone());
        let token = create_test_token(
            "test-issuer",
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        let gate = Arc::new(RequestGate::default());
        let app = create_gated_credentials_router(state.clone(), gate.clone());
        let request = Request::builder()
            .uri("/credentials")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let in_flight = tokio::spawn(app.oneshot(request));
        gate.entered.notified().await;

        std::fs::write(&file, "version: 1\nissuers: []\nadmins: []\n").unwrap();
        registry_handle.reload().unwrap();
        gate.release.notify_one();
        let response = in_flight.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let registration: crate::server::handlers::issue_credential::RegistrationResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(registration.issuer, "test-issuer");
        assert_eq!(registration.aggregation_id.0, aggregation_id);
        assert_eq!(registration.aggregation_uri, None);

        assert_eq!(
            call_with_token(create_test_router(state), token)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn documented_registry_key_format_authenticates() {
        let public_key = test_public_jwk();
        let mut jwk = serde_json::to_value(public_key.jwk()).unwrap();
        let jwk = jwk.as_object_mut().unwrap();
        jwk.remove("kid");
        jwk.remove("alg");
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "test-issuer",
                "aggregation_id": uuid::Uuid::new_v4(),
                "keys": [{"kid": "test-key", "alg": "ES256", "jwk": jwk}],
            }],
            "admins": []
        }))
        .unwrap();
        let mut state = test_app_state(None).await;
        state.set_issuer_registry(Arc::new(
            issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));

        let token = create_test_token(
            "test-issuer",
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        assert_eq!(
            call_with_token(create_test_router(state), token)
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn admin_key_cannot_authenticate_an_issuer_management_request() {
        let key = test_public_jwk();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [],
            "admins": [{
                "id": "portal-backend",
                "scopes": ["issuers:write"],
                "keys": [{
                    "kid": key.key_id(),
                    "alg": format!("{:?}", key.algorithm()),
                    "jwk": key.jwk(),
                }],
            }],
        }))
        .unwrap();
        let mut state = test_app_state(None).await;
        state.set_issuer_registry(Arc::new(
            issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));
        let token = create_test_token(
            "portal-backend",
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        assert_eq!(
            call_with_token(create_test_router(state), token)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn admin_lifecycle_auth_requires_issuer_write_scope() {
        async fn admin_handler(Extension(admin): Extension<AuthenticatedAdmin>) -> String {
            admin.id
        }
        let key = test_public_jwk();
        let token = create_test_token(
            "portal-backend",
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        for (scopes, expected) in [
            (vec!["issuers:write"], StatusCode::OK),
            (vec!["issuers:read"], StatusCode::UNAUTHORIZED),
        ] {
            let registry = serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [],
                "admins": [{
                    "id": "portal-backend",
                    "scopes": scopes,
                    "keys": [{"kid": key.key_id(), "alg": "ES256", "jwk": key.jwk()}],
                }],
            }))
            .unwrap();
            let mut state = test_app_state(None).await;
            state.set_issuer_registry(Arc::new(
                issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
            ));
            let app = Router::new()
                .route("/test", get(admin_handler))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    admin_auth,
                ))
                .with_state(state);
            assert_eq!(call_with_token(app, token.clone()).await.status(), expected);
        }
    }

    fn set_registry(state: &mut AppState, issuer: &str, keys: &[PublicJwk]) {
        let entries: Vec<_> = keys
            .iter()
            .map(|key| {
                serde_json::json!({
                    "kid": key.key_id(),
                    "alg": format!("{:?}", key.algorithm()),
                    "jwk": key.jwk(),
                })
            })
            .collect();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": issuer,
                "aggregation_id": uuid::Uuid::new_v4(),
                "keys": entries,
            }],
            "admins": []
        }))
        .unwrap();
        state.set_issuer_registry(Arc::new(
            issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));
    }

    async fn call_with_token(app: Router, token: String) -> axum::response::Response {
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Basic invalid_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer invalid_jwt_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_issuer_not_found_in_database() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let private_key = test_ec_private_pem();
        let secret = EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap();
        let token = create_test_token("unregistered-issuer", &secret, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, "Ok");
    }

    #[tokio::test]
    async fn test_token_verification_failure_wrong_key() {
        let wrong_private_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi\najH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2\n7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5\n-----END PRIVATE KEY-----";

        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);

        let wrong_encoding_key = EncodingKey::from_ec_pem(wrong_private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &wrong_encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);

        let now = now();

        let expired_claims = TestClaims {
            iss: "test-issuer".to_string(),
            iat: now - 400,
            nbf: None,
            exp: now - 100,
        };

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let header = management_header();
        let token = encode(&header, &expired_claims, &encoding_key).unwrap();

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_issuer_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iat": now,
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_expiration_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_issued_at_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_issuer_claim_must_match_the_registered_kid_owner() {
        let mut state = test_state_with_registered_issuer().await;
        let mut other_key: serde_json::Value =
            serde_json::from_slice(rotation_public_jwk().as_bytes()).unwrap();
        other_key["kid"] = serde_json::json!("other-key");
        let other_public = crate::domain::models::credential::PublicJwk::try_new(
            serde_json::to_vec(&other_key).unwrap(),
        )
        .unwrap();
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("another-issuer".into()),
                public_key: crate::domain::models::credential::PublicJwk::try_new(
                    serde_json::to_vec(&other_key).unwrap(),
                )
                .unwrap(),
            })
            .await
            .unwrap();
        let own_public = test_public_jwk();
        set_registry(&mut state, "test-issuer", std::slice::from_ref(&own_public));
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [
                {"id": "test-issuer", "aggregation_id": uuid::Uuid::new_v4(), "keys": [{"kid": own_public.key_id(), "alg": format!("{:?}", own_public.algorithm()), "jwk": own_public.jwk()}]},
                {"id": "another-issuer", "aggregation_id": uuid::Uuid::new_v4(), "keys": [{"kid": other_public.key_id(), "alg": format!("{:?}", other_public.algorithm()), "jwk": other_public.jwk()}]}
            ], "admins": []
        })).unwrap();
        state.set_issuer_registry(Arc::new(
            issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));
        let app = create_test_router(state);
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        let token = sign_claims(
            serde_json::json!({"iss":"another-issuer", "iat":now, "exp":now + 300}),
            &secret,
        );

        assert_eq!(
            call_with_token(app.clone(), token).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut own_header = management_header();
        own_header.kid = Some("other-key".into());
        let own_token = sign_claims_with_header(
            serde_json::json!({"iss":"another-issuer", "iat":now, "exp":now + 300}),
            &secret,
            own_header,
        );
        assert_eq!(
            call_with_token(app, own_token).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn key_rotation_accepts_overlap_and_rejects_removed_key_after_reload() {
        let old_key = test_public_jwk();
        let new_key = rotation_public_jwk();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("issuers.yaml");
        let aggregation_id = uuid::Uuid::new_v4();
        let registry_yaml = |keys: &[PublicJwk]| {
            let keys = keys
                .iter()
                .map(|key| {
                    serde_json::json!({
                        "kid": key.key_id(),
                        "alg": format!("{:?}", key.algorithm()),
                        "jwk": key.jwk(),
                    })
                })
                .collect::<Vec<_>>();
            serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "test-issuer",
                    "aggregation_id": aggregation_id,
                    "keys": keys,
                }],
                "admins": []
            }))
            .unwrap()
        };
        std::fs::write(&file, registry_yaml(std::slice::from_ref(&old_key))).unwrap();

        let mut state = test_app_state(None).await;
        let registry = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
        state.set_issuer_registry(registry.clone());
        let app = create_test_router(state);
        let now = now();
        let old_token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            management_header(),
        );
        let mut new_header = management_header();
        new_header.kid = Some("rotation-key".into());
        let new_token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &EncodingKey::from_ec_pem(rotation_private_pem().as_bytes()).unwrap(),
            new_header,
        );

        assert_eq!(
            call_with_token(app.clone(), old_token.clone())
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            call_with_token(app.clone(), new_token.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );

        std::fs::write(&file, registry_yaml(&[old_key.clone(), new_key.clone()])).unwrap();
        registry.reload().unwrap();
        assert_eq!(
            call_with_token(app.clone(), old_token.clone())
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            call_with_token(app.clone(), new_token.clone())
                .await
                .status(),
            StatusCode::OK
        );

        std::fs::write(&file, "version: invalid").unwrap();
        assert!(registry.reload().is_err());
        assert_eq!(
            call_with_token(app.clone(), old_token.clone())
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            call_with_token(app.clone(), new_token.clone())
                .await
                .status(),
            StatusCode::OK
        );

        std::fs::write(&file, registry_yaml(std::slice::from_ref(&new_key))).unwrap();
        registry.reload().unwrap();
        assert_eq!(
            call_with_token(app.clone(), old_token).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call_with_token(app, new_token).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn disabling_static_issuer_stops_writes_on_both_replicas_but_keeps_public_list() {
        use crate::server::handlers::{get_status_list, publish_status_route};

        async fn write(app: Router, list_id: &str, token: &str) -> StatusCode {
            app.oneshot(
                Request::builder()
                    .method(axum::http::Method::PUT)
                    .uri(format!("/api/v1/status-lists/{list_id}/statuses/"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"statuses":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }

        async fn read(app: Router, list_id: &str) -> StatusCode {
            app.oneshot(
                Request::builder()
                    .uri(format!("/api/v1/status-lists/{list_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }

        let public_key = test_public_jwk();
        let aggregation_id = uuid::Uuid::new_v4();
        let registry_yaml = |disabled| {
            serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "test-issuer",
                    "aggregation_id": aggregation_id,
                    "disabled": disabled,
                    "keys": [{
                        "kid": public_key.key_id(),
                        "alg": "ES256",
                        "jwk": public_key.jwk(),
                    }],
                }],
                "admins": []
            }))
            .unwrap()
        };
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("issuers.yaml");
        std::fs::write(&file, registry_yaml(false)).unwrap();
        let first_registry = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
        let second_registry = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());

        let mut first_state = test_app_state(None).await;
        let mut second_state = first_state.clone();
        first_state.set_issuer_registry(first_registry.clone());
        second_state.set_issuer_registry(second_registry.clone());
        let router = |state: AppState| {
            let management = Router::new()
                .route(
                    "/api/v1/status-lists/{list_id}/statuses/",
                    put(publish_status_route),
                )
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth));
            let public =
                Router::new().route("/api/v1/status-lists/{list_id}", get(get_status_list));
            Router::new()
                .merge(management)
                .merge(public)
                .with_state(state)
        };
        let first_app = router(first_state);
        let second_app = router(second_state);
        let token = create_test_token(
            "test-issuer",
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        let published_list = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            write(first_app.clone(), &published_list, &token).await,
            StatusCode::CREATED
        );

        std::fs::write(&file, registry_yaml(true)).unwrap();
        first_registry.reload().unwrap();
        second_registry.reload().unwrap();
        assert_eq!(
            write(first_app.clone(), &uuid::Uuid::new_v4().to_string(), &token).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            write(
                second_app.clone(),
                &uuid::Uuid::new_v4().to_string(),
                &token
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(read(first_app, &published_list).await, StatusCode::OK);
        assert_eq!(read(second_app, &published_list).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn watcher_rotates_keys_and_keeps_last_known_good_registry() {
        let old_key = test_public_jwk();
        let new_key = rotation_public_jwk();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("issuers.yaml");
        let aggregation_id = uuid::Uuid::new_v4();
        let registry_yaml = |keys: &[PublicJwk]| {
            let keys = keys
                .iter()
                .map(|key| {
                    serde_json::json!({
                        "kid": key.key_id(),
                        "alg": format!("{:?}", key.algorithm()),
                        "jwk": key.jwk(),
                    })
                })
                .collect::<Vec<_>>();
            serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "test-issuer",
                    "aggregation_id": aggregation_id,
                    "keys": keys,
                }],
                "admins": []
            }))
            .unwrap()
        };
        std::fs::write(&file, registry_yaml(std::slice::from_ref(&old_key))).unwrap();

        let mut state = test_app_state(None).await;
        let registry = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
        state.set_issuer_registry(registry.clone());
        let registry_for_assert = registry.clone();
        let watched_registry = registry.clone();
        FileWatcher::new(vec![file.clone()], Duration::from_secs(1)).spawn(
            "issuer_registry",
            move || {
                let registry = watched_registry.clone();
                async move {
                    // Production keeps serving the active snapshot when a reload
                    // is invalid; this test exercises that same behavior.
                    if registry.reload().is_err() {
                        registry.record_reload_failure();
                    }
                }
            },
        );
        // The watcher first fingerprints the initial file asynchronously.
        sleep(Duration::from_millis(750)).await;
        let app = create_test_router(state);
        let now = now();
        let old_token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap(),
            management_header(),
        );
        let mut new_header = management_header();
        new_header.kid = Some("rotation-key".into());
        let new_token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &EncodingKey::from_ec_pem(rotation_private_pem().as_bytes()).unwrap(),
            new_header,
        );

        let mut gated_state = test_app_state(None).await;
        gated_state.set_issuer_registry(registry.clone());
        let request_gate = Arc::new(RequestGate::default());
        let in_flight_app = create_gated_test_router(gated_state, request_gate.clone());
        let in_flight = tokio::spawn(call_with_token(in_flight_app, old_token.clone()));
        timeout(Duration::from_secs(2), request_gate.entered.notified())
            .await
            .expect("request authenticated and reached the blocked handler before reload");

        std::fs::write(&file, registry_yaml(&[old_key.clone(), new_key.clone()])).unwrap();
        let rotation = timeout(Duration::from_secs(5), async {
            loop {
                assert_eq!(
                    call_with_token(app.clone(), old_token.clone())
                        .await
                        .status(),
                    StatusCode::OK
                );
                if call_with_token(app.clone(), new_token.clone())
                    .await
                    .status()
                    == StatusCode::OK
                {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            rotation.is_ok(),
            "watcher did not load the overlapping rotation key; registry has {} key(s)",
            registry_for_assert.snapshot().key_count()
        );
        request_gate.release.notify_one();
        assert_eq!(
            in_flight.await.unwrap().status(),
            StatusCode::OK,
            "an authenticated in-flight request must finish across registry replacement"
        );

        std::fs::write(&file, registry_yaml(std::slice::from_ref(&new_key))).unwrap();
        let retirement = timeout(Duration::from_secs(5), async {
            loop {
                let new_status = call_with_token(app.clone(), new_token.clone())
                    .await
                    .status();
                assert_eq!(new_status, StatusCode::OK);
                if call_with_token(app.clone(), old_token.clone())
                    .await
                    .status()
                    == StatusCode::UNAUTHORIZED
                {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            retirement.is_ok(),
            "watcher did not revoke the retired key while keeping the replacement trusted"
        );

        let mut duplicate_key_jwk = serde_json::to_value(old_key.jwk()).unwrap();
        duplicate_key_jwk
            .as_object_mut()
            .unwrap()
            .retain(|field, _| field != "kid" && field != "alg");
        let duplicate_kid_registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "test-issuer",
                "aggregation_id": aggregation_id,
                "keys": [
                    {"kid": "duplicate-key", "alg": "ES256", "jwk": duplicate_key_jwk.clone()},
                    {"kid": "duplicate-key", "alg": "ES256", "jwk": duplicate_key_jwk},
                ],
            }],
            "admins": []
        }))
        .unwrap();
        for invalid in [
            String::new(),
            "version: 1\nissuers:\n  - id: test-issuer\n    id: disabled\n".to_owned(),
            duplicate_kid_registry,
            "version: 1\nissuers:".to_owned(),
        ] {
            let failures_before = registry_for_assert.reload_failure_count();
            std::fs::write(&file, invalid).unwrap();
            timeout(Duration::from_secs(5), async {
                while registry_for_assert.reload_failure_count() == failures_before {
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("invalid update was not checked by the watcher");
            assert_eq!(
                call_with_token(app.clone(), new_token.clone())
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let failures_before = registry_for_assert.reload_failure_count();
        std::fs::remove_file(&file).unwrap();
        timeout(Duration::from_secs(5), async {
            while registry_for_assert.reload_failure_count() == failures_before {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("missing registry was not checked by the watcher");
        assert_eq!(
            call_with_token(app, new_token).await.status(),
            StatusCode::OK
        );
    }

    #[test]
    fn watcher_counts_failed_registry_reloads_without_reducing_trust() {
        let metrics = metrics_after(async {
            let directory = tempfile::tempdir().unwrap();
            let file = directory.path().join("issuers.yaml");
            std::fs::write(
                &file,
                serde_saphyr::to_string(&serde_json::json!({
                    "version": 1,
                    "issuers": [{
                        "id": "test-issuer",
                        "aggregation_id": uuid::Uuid::new_v4(),
                        "keys": [{
                            "kid": "test-key", "alg": "ES256",
                            "jwk": test_public_jwk().jwk(),
                        }],
                    }],
                    "admins": []
                }))
                .unwrap(),
            )
            .unwrap();
            let registry = Arc::new(issuer_registry::RegistryHandle::load(&file).unwrap());
            let state = test_app_state(None).await;
            crate::setup::spawn_issuer_registry_watcher(
                registry.clone(),
                state.service,
                None,
                file.clone(),
                Duration::from_secs(1),
            );
            let duplicate_key_jwk = serde_json::to_value(test_public_jwk().jwk()).unwrap();
            let mut duplicate_key_jwk = duplicate_key_jwk;
            duplicate_key_jwk
                .as_object_mut()
                .unwrap()
                .retain(|field, _| field != "kid" && field != "alg");
            let duplicate_kid_registry = serde_saphyr::to_string(&serde_json::json!({
                "version": 1,
                "issuers": [{
                    "id": "test-issuer",
                    "aggregation_id": uuid::Uuid::new_v4(),
                    "keys": [
                        {"kid": "duplicate-key", "alg": "ES256", "jwk": duplicate_key_jwk.clone()},
                        {"kid": "duplicate-key", "alg": "ES256", "jwk": duplicate_key_jwk},
                    ],
                }],
                "admins": []
            }))
            .unwrap();
            for invalid in [
                String::new(),
                duplicate_kid_registry,
                "version: 1\nissuers:".to_owned(),
            ] {
                let failures_before = registry.reload_failure_count();
                std::fs::write(&file, invalid).unwrap();
                timeout(Duration::from_secs(5), async {
                    while registry.reload_failure_count() == failures_before {
                        sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .expect("invalid update was not checked by the watcher");
                assert!(registry.resolve("test-key").is_some());
            }
            let failures_before = registry.reload_failure_count();
            std::fs::remove_file(&file).unwrap();
            timeout(Duration::from_secs(5), async {
                while registry.reload_failure_count() == failures_before {
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("missing registry was not checked by the watcher");
            assert!(registry.resolve("test-key").is_some());
        });
        let reload_failures = metrics
            .lines()
            .find(|line| line.starts_with("issuer_registry_reload_failures_total"))
            .expect("issuer registry reload failures metric is exported");
        let total: u64 = reload_failures
            .split_whitespace()
            .last()
            .unwrap()
            .parse()
            .unwrap();
        assert!(total >= 4, "{reload_failures}");
    }

    #[tokio::test]
    async fn test_future_issued_at_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now + 120,
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_future_not_before_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "nbf": now + 120,
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_too_long_lived_token_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "exp": now + 301
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_wrong_audience_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "aud": "other-service",
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_audience_claim_is_ignored_when_no_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "aud": "other-service",
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_matching_audience_claim_succeeds_when_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        for audience in [
            serde_json::json!("status-list-server-management"),
            serde_json::json!(["other-service", "status-list-server-management"]),
        ] {
            let token = sign_claims(
                serde_json::json!({
                    "iss": "test-issuer", "iat": now, "aud": audience, "exp": now + 300
                }),
                &encoding_key,
            );
            assert_eq!(
                call_with_token(app.clone(), token).await.status(),
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn test_missing_audience_claim_is_rejected_when_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "exp": now + 300
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_errors_have_generic_response_message() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer invalid_jwt_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_token");
        assert_eq!(body["error_description"], "Invalid authentication token");
    }

    #[tokio::test]
    async fn test_critical_header_is_rejected() {
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        let mut jwt_header = management_header();
        jwt_header.crit = Some(vec!["custom".to_string()]);
        let token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &secret,
            jwt_header,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );
    }

    #[tokio::test]
    async fn test_token_jwk_header_is_ignored() {
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        let mut jwt_header = management_header();
        jwt_header.typ = Some("Application/Statuslist-management+jwt".to_string());
        let attacker_key = EncodingKey::from_ec_pem(
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi\najH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2\n7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5\n-----END PRIVATE KEY-----".as_bytes(),
        )
        .unwrap();
        jwt_header.jwk = Some(
            jsonwebtoken::jwk::Jwk::from_encoding_key(&attacker_key, Algorithm::ES256).unwrap(),
        );
        let token = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &secret,
            jwt_header.clone(),
        );

        assert_eq!(
            call_with_token(app.clone(), token).await.status(),
            StatusCode::OK
        );

        // An attacker cannot substitute the embedded key for the registered one.
        let attack = sign_claims_with_header(
            serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
            &attacker_key,
            jwt_header,
        );
        let response = call_with_token(app, attack).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_token"
        );
    }

    #[tokio::test]
    async fn test_missing_kid_and_wrong_type_are_rejected() {
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        for (kid, typ) in [
            (None, Some("statuslist-management+jwt")),
            (Some("test-key"), Some("JWT")),
            (Some("test-key"), None),
        ] {
            let state = test_state_with_registered_issuer().await;
            let app = create_test_router(state);
            let mut jwt_header = management_header();
            jwt_header.kid = kid.map(str::to_owned);
            jwt_header.typ = typ.map(str::to_owned);
            let token = sign_claims_with_header(
                serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300}),
                &secret,
                jwt_header,
            );
            assert_eq!(
                call_with_token(app, token).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn test_algorithm_must_be_allowed_and_match_registered_key() {
        let now = now();
        let claims = serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300});
        let mut hs_header = management_header();
        hs_header.alg = Algorithm::HS256;
        let hs_token = sign_claims_with_header(
            claims.clone(),
            &EncodingKey::from_secret(b"test-secret"),
            hs_header,
        );

        let ec_secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let valid_es256 = sign_claims(claims, &ec_secret);
        let mut parts = valid_es256.split('.');
        let _original_header = parts.next().unwrap();
        let payload = parts.next().unwrap();
        let signature = parts.next().unwrap();
        let es384_header = URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES384","kid":"test-key","typ":"statuslist-management+jwt"}"#);
        let mismatched_token = format!("{es384_header}.{payload}.{signature}");

        for token in [hs_token, mismatched_token] {
            let state = test_state_with_registered_issuer().await;
            let app = create_test_router(state);
            assert_eq!(
                call_with_token(app, token).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn test_unknown_key_and_bad_signature_have_identical_auth_responses() {
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        let claims = serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now + 300});
        let state = test_app_state(None).await;
        let mut unknown_header = management_header();
        unknown_header.kid = Some("unknown-key".to_string());
        let unknown = sign_claims_with_header(claims.clone(), &secret, unknown_header);
        let unknown_response = call_with_token(create_test_router(state), unknown).await;

        let state = test_state_with_registered_issuer().await;
        let wrong_secret = EncodingKey::from_ec_pem(
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi\najH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2\n7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5\n-----END PRIVATE KEY-----".as_bytes(),
        ).unwrap();
        let bad_signature = sign_claims(claims, &wrong_secret);
        let bad_signature_response =
            call_with_token(create_test_router(state), bad_signature).await;

        assert_eq!(unknown_response.status(), bad_signature_response.status());
        assert_eq!(
            unknown_response.headers()[header::WWW_AUTHENTICATE],
            bad_signature_response.headers()[header::WWW_AUTHENTICATE]
        );
        let unknown_body = to_bytes(unknown_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let bad_signature_body = to_bytes(bad_signature_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(unknown_body, bad_signature_body);
    }

    #[tokio::test]
    async fn all_supported_management_algorithms_authenticate() {
        use crate::domain::models::credential::{Credential, PublicJwk};
        for algorithm in [
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::EdDSA,
            Algorithm::PS256,
        ] {
            let secret = match algorithm {
                Algorithm::ES256 => {
                    EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap()
                }
                Algorithm::ES384 => {
                    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
                    EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap()
                }
                Algorithm::EdDSA => {
                    let key =
                        crate::crypto::SigningKey::generate(crate::crypto::SigningAlgorithm::EdDsa)
                            .unwrap();
                    EncodingKey::from_ed_pem(key.to_pkcs8_pem().unwrap().as_bytes()).unwrap()
                }
                Algorithm::PS256 => EncodingKey::from_rsa_pem(include_bytes!(
                    "../../../test_data/gcloud_test_key.dummy.pem"
                ))
                .unwrap(),
                _ => unreachable!(),
            };
            let mut jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&secret, algorithm).unwrap();
            jwk.common.key_id = Some("algorithm-key".into());
            let mut state = test_app_state(None).await;
            state
                .service
                .publish_credential(Credential {
                    issuer: Issuer("algorithm-issuer".into()),
                    public_key: PublicJwk::try_new(serde_json::to_vec(&jwk).unwrap()).unwrap(),
                })
                .await
                .unwrap();
            let public_key = state
                .service
                .find_credential_by_kid("algorithm-key")
                .await
                .unwrap()
                .unwrap()
                .public_key;
            set_registry(&mut state, "algorithm-issuer", &[public_key]);
            let mut header = Header::new(algorithm);
            header.kid = Some("algorithm-key".into());
            header.typ = Some(MANAGEMENT_TOKEN_TYPE.into());
            let now = now();
            let token = sign_claims_with_header(
                serde_json::json!({"iss":"algorithm-issuer", "iat":now, "exp":now+300}),
                &secret,
                header,
            );
            assert_eq!(
                call_with_token(create_test_router(state), token)
                    .await
                    .status(),
                StatusCode::OK,
                "{algorithm:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_token_failures_have_identical_responses() {
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["management-tests".into()];
        let app = create_test_router(state);
        let secret = EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap();
        let now = now();
        let valid = serde_json::json!({"iss":"test-issuer", "iat":now, "exp":now+300, "aud":"management-tests"});
        let mut cases = vec![("malformed JWT", "malformed".to_owned())];
        for (name, claims) in [
            ("missing iss", {
                let mut v = valid.clone();
                v.as_object_mut().unwrap().remove("iss");
                v
            }),
            ("missing iat", {
                let mut v = valid.clone();
                v.as_object_mut().unwrap().remove("iat");
                v
            }),
            ("missing exp", {
                let mut v = valid.clone();
                v.as_object_mut().unwrap().remove("exp");
                v
            }),
            ("missing aud", {
                let mut v = valid.clone();
                v.as_object_mut().unwrap().remove("aud");
                v
            }),
            ("wrong iss", {
                let mut v = valid.clone();
                v["iss"] = "other-issuer".into();
                v
            }),
            ("wrong aud", {
                let mut v = valid.clone();
                v["aud"] = "other-audience".into();
                v
            }),
            ("expired", {
                let mut v = valid.clone();
                v["iat"] = (now - 1000).into();
                v["exp"] = (now - 700).into();
                v
            }),
            ("future iat", {
                let mut v = valid.clone();
                v["iat"] = (now + 1000).into();
                v["exp"] = (now + 1300).into();
                v
            }),
            ("future nbf", {
                let mut v = valid.clone();
                v["nbf"] = (now + 1000).into();
                v
            }),
            ("zero lifetime", {
                let mut v = valid.clone();
                v["exp"] = now.into();
                v
            }),
            ("negative lifetime", {
                let mut v = valid.clone();
                v["exp"] = (now - 1).into();
                v
            }),
            ("excess lifetime", {
                let mut v = valid.clone();
                v["exp"] = (now + 301).into();
                v
            }),
        ] {
            cases.push((name, sign_claims(claims, &secret)));
        }
        for (name, header) in [
            ("missing kid", {
                let mut h = management_header();
                h.kid = None;
                h
            }),
            ("empty kid", {
                let mut h = management_header();
                h.kid = Some(String::new());
                h
            }),
            ("unknown kid", {
                let mut h = management_header();
                h.kid = Some("unknown-key".into());
                h
            }),
            ("missing typ", {
                let mut h = management_header();
                h.typ = None;
                h
            }),
            ("wrong typ", {
                let mut h = management_header();
                h.typ = Some("JWT".into());
                h
            }),
            ("crit", {
                let mut h = management_header();
                h.crit = Some(vec!["custom".into()]);
                h
            }),
        ] {
            cases.push((
                name,
                sign_claims_with_header(valid.clone(), &secret, header),
            ));
        }
        let mut hs_header = management_header();
        hs_header.alg = Algorithm::HS256;
        cases.push((
            "disallowed alg",
            sign_claims_with_header(
                valid.clone(),
                &EncodingKey::from_secret(b"attacker"),
                hs_header,
            ),
        ));
        let original = sign_claims(valid.clone(), &secret);
        let (_, tail) = original.split_once('.').unwrap();
        let mut mismatch = management_header();
        mismatch.alg = Algorithm::ES384;
        cases.push((
            "algorithm mismatch",
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&mismatch).unwrap()),
                tail
            ),
        ));
        let wrong_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let wrong_secret = EncodingKey::from_ec_pem(wrong_key.serialize_pem().as_bytes()).unwrap();
        cases.push(("bad signature", sign_claims(valid.clone(), &wrong_secret)));
        let mut injected = management_header();
        injected.jwk = Some(
            jsonwebtoken::jwk::Jwk::from_encoding_key(&wrong_secret, Algorithm::ES256).unwrap(),
        );
        cases.push((
            "embedded attacker key",
            sign_claims_with_header(valid, &wrong_secret, injected),
        ));

        let expected = AuthenticationError::InvalidToken.into_response();
        let challenge = expected.headers()[header::WWW_AUTHENTICATE].clone();
        let content_type = expected.headers()[header::CONTENT_TYPE].clone();
        let body = to_bytes(expected.into_body(), usize::MAX).await.unwrap();
        for (name, token) in cases {
            let response = call_with_token(app.clone(), token).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                challenge,
                "{name}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                content_type,
                "{name}"
            );
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                body,
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn empty_bearer_headers_are_uniform_invalid_tokens() {
        let app = create_test_router(test_app_state(None).await);
        let expected = AuthenticationError::InvalidToken.into_response();
        let body = to_bytes(expected.into_body(), usize::MAX).await.unwrap();
        for value in ["Bearer", "Bearer ", "bEaReR", "Bearer   ", "Bearer\t"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/test")
                        .header(header::AUTHORIZATION, value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value:?}");
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                "Bearer error=\"invalid_token\"",
                "{value:?}"
            );
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                body,
                "{value:?}"
            );
        }
        for value in [None, Some("Basic credentials")] {
            let mut request = Request::builder().uri("/test");
            if let Some(value) = value {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        }
    }

    #[tokio::test]
    async fn test_authenticated_issuer_extractor_returns_principal() {
        let private_pem = test_ec_private_pem();
        let mut state = test_app_state(None).await;

        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();
        let public_key = test_public_jwk();
        set_registry(&mut state, "test-issuer", &[public_key]);

        async fn extension_test_handler(principal: AuthenticatedIssuer) -> String {
            assert_eq!(principal.issuer(), &Issuer("test-issuer".into()));
            principal.into_issuer().0
        }

        let app = Router::new()
            .route("/test", get(extension_test_handler))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state);

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, "test-issuer");
    }

    #[tokio::test]
    async fn test_authenticated_issuer_extractor_returns_401_when_context_missing() {
        let state = test_app_state(None).await;

        async fn principal_handler(_principal: AuthenticatedIssuer) -> &'static str {
            "Ok"
        }

        let app = Router::new()
            .route("/test", get(principal_handler))
            .with_state(state);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "missing_auth_context");
    }
}
