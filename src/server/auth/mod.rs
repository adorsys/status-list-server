//! Authentication middleware validating bearer JWTs against registered issuer credentials.
//!
//! Claim validation policy for management tokens:
//! - `iss` (required): must match a registered issuer (bounded and used as the
//!   credential lookup key).
//! - `exp` (required): must be in the future (within the configured leeway) and,
//!   when a maximum lifetime is configured, must not extend beyond
//!   `now + max_lifetime + leeway`.
//! - `iat` (required): must not be in the future beyond the leeway, so a
//!   server-clock-anchored bound on `exp` cannot be bypassed via a future `iat`.
//! - `nbf` (optional): when present, must be in the past (within the configured leeway).
//! - `aud` (required when `expected_audience` is configured): must match it.
//!
//! Verification is pinned to the registered key's algorithm family; a token's
//! unverified `alg` header is never trusted. HMAC/shared-secret (`oct`) keys
//! are rejected at registration (400 `invalid_public_jwk`); the middleware
//! keeps the HMAC gate as defense-in-depth only.
//!
//! Failures are mapped to a generic `401` `invalid_token` so the response never
//! discloses which claim failed, which verification layer failed, or any token
//! details, and an unregistered issuer is indistinguishable from an invalid
//! token.

pub mod errors;

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::header;
use jsonwebtoken::{AlgorithmFamily, DecodingKey, Validation, get_current_timestamp};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::server::AppState;

/// Upper bound (bytes) on an unverified `iss` before it is used as a database
/// lookup key and echoed into log lines. Bounds the input size so an attacker
/// cannot force a huge allocation or database query.
const MAX_ISSUER_LEN: usize = 512;

/// Sanitizes an attacker-controlled string for embedding in log lines. Log
/// sinks vary: structured sinks escape control characters, but plain-text
/// sinks may not, and a control byte (e.g. newline) could otherwise forge log
/// entries. Replaces all C0/C1 control characters so the value is safe to
/// interpolate regardless of the sink.
fn sanitize_for_log(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// RFC 7519 §4.1.3: `aud` is either a single string or an array of strings.
/// An untagged enum gives that flexibility with real type safety, rejecting
/// `aud: 42` or `aud: {}` at deserialization time.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

/// RFC 7519 §2 `NumericDate`: a JSON number that may be non-integral.
/// Deserialize as `f64` and coerce (matching the jsonwebtoken crate) so a token
/// with `"exp": 1712345678.0` succeeds instead of failing opaque deserialization.
fn deserialize_numeric_date<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = f64::deserialize(deserializer)?;
    if !value.is_finite() {
        return Err(D::Error::custom("NumericDate must be a finite number"));
    }
    Ok(value.round() as u64)
}

fn deserialize_option_numeric_date<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let present = Option::<serde_json::Value>::deserialize(deserializer)?;
    match present {
        None => Ok(None),
        Some(value) => {
            let n = value
                .as_f64()
                .ok_or_else(|| D::Error::custom("NumericDate must be a finite number"))?;
            if !n.is_finite() {
                return Err(D::Error::custom("NumericDate must be a finite number"));
            }
            Ok(Some(n.round() as u64))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    #[serde(deserialize_with = "deserialize_numeric_date")]
    exp: u64,
    #[serde(deserialize_with = "deserialize_numeric_date")]
    iat: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_option_numeric_date"
    )]
    nbf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aud: Option<Audience>,
}

/// Authentication middleware acting as a safeguard for unauthorized issuers
pub async fn auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    use jsonwebtoken::dangerous::insecure_decode;

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(AuthenticationError::InvalidAuthorizationHeader)?;

    let issuer = insecure_decode::<Claims>(token)
        .map_err(|e| {
            tracing::error!("Failed to decode JWT claims: {e}");
            AuthenticationError::InvalidClaims
        })?
        .claims
        .iss;

    // Bound the unverified `iss` before using it as a DB lookup key so an
    // attacker cannot force a huge allocation or query.
    if issuer.trim().is_empty() || issuer.len() > MAX_ISSUER_LEN {
        tracing::warn!(
            issuer_len = issuer.len(),
            "Rejecting token with out-of-bounds issuer"
        );
        return Err(AuthenticationError::InvalidClaims);
    }

    // A log-safe form of `iss` for tracing. `iss` is attacker-controlled (the
    // signature is not yet verified) and may contain control characters that
    // a plain-text log sink would not escape. The raw value is still used as
    // the exact database lookup key below.
    let safe_issuer = sanitize_for_log(&issuer);

    let credential = state.service.find_credential(&issuer).await.map_err(|e| {
        tracing::error!(issuer = %safe_issuer, error = ?e, "Failed to find credential");
        AuthenticationError::InternalServer
    })?;

    // An absent credential is deliberately folded into the generic `invalid_token`
    // wire code (not `issuer_not_found`) so the response is not an enumeration
    // oracle for registered issuers. The distinction lives in logs only.
    let Some(credential) = credential else {
        tracing::warn!(issuer = %safe_issuer, "Rejecting token from unregistered issuer");
        return Err(AuthenticationError::InvalidClaims);
    };

    let public_key = serde_json::from_slice(credential.public_key.as_bytes())
        .map_err(|_| AuthenticationError::InternalServer)?;
    let decoding_key = DecodingKey::from_jwk(&public_key).map_err(|e| {
        tracing::error!(issuer = %safe_issuer, error = %e, "Failed to build decoding key");
        AuthenticationError::InternalServer
    })?;

    // Pin verification to the registered key's algorithm family rather than
    // trusting the unverified header `alg` (which would otherwise feed a
    // tautological family check). Shared-secret (HMAC) keys are rejected here
    // as a defense-in-depth gate: `oct` keys map to the HMAC family in
    // jsonwebtoken and are already rejected at registration (`PublicJwk::try_new`).
    let family = decoding_key.family();
    if family == AlgorithmFamily::Hmac {
        tracing::warn!(issuer = %safe_issuer, "Rejecting HMAC management key");
        return Err(AuthenticationError::UnsupportedAlgorithm);
    }
    let mut validation = Validation::new_for_family(family);
    validation.set_issuer(&[&credential.issuer.0]);
    validation.leeway = state.auth.leeway_secs;
    validation.validate_nbf = true;
    if let Some(expected_audience) = &state.auth.expected_audience {
        validation.set_audience(&[expected_audience]);
        // `set_audience` only sets the audience; it does not make `aud` required.
        // Without this an omitted `aud` claim falls through as accepted.
        validation.required_spec_claims.insert("aud".to_owned());
    } else {
        // `aud` is optional when no audience is configured. Leave validate_aud
        // enabled would otherwise reject any token that merely carries an `aud`
        // claim (jsonwebtoken rejects it when the accepted audience set is empty).
        validation.validate_aud = false;
    }

    let token_data =
        jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).map_err(|e| match &e
            .kind()
        {
            jsonwebtoken::errors::ErrorKind::InvalidSignature
            | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
            | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
            | jsonwebtoken::errors::ErrorKind::RsaFailedSigning => {
                tracing::warn!(issuer = %safe_issuer, error = %e, "Token signature verification failed");
                AuthenticationError::InvalidSignature
            }
            _ => {
                tracing::warn!(issuer = %safe_issuer, error = %e, "Token claim validation failed");
                AuthenticationError::InvalidClaims
            }
        })?;

    // Anchor validation to the server clock. `iat` is issuer-controlled and, by
    // design, never compared by jsonwebtoken; only `exp` is anchored to real time.
    let now = get_current_timestamp();

    // Reject tokens that are not yet valid (iat in the future beyond leeway).
    if token_data.claims.iat > now.saturating_add(state.auth.leeway_secs) {
        tracing::warn!(issuer = %safe_issuer, "Rejecting token with future iat");
        return Err(AuthenticationError::InvalidClaims);
    }

    // Enforce an explicit upper bound on token lifetime when configured. The
    // absolute bound on `exp` is the primary control: it is clock-anchored and
    // cannot be bypassed by an attacker choosing `iat`. `exp - iat` remains as
    // a secondary relative assertion.
    if let Some(max_lifetime) = state.auth.max_token_lifetime_secs {
        let exp_cap = now
            .saturating_add(max_lifetime)
            .saturating_add(state.auth.leeway_secs);
        if token_data.claims.exp > exp_cap {
            tracing::warn!(
                issuer = %safe_issuer,
                exp = token_data.claims.exp,
                max_lifetime_secs = max_lifetime,
                "Rejecting token exceeding maximum absolute lifetime"
            );
            return Err(AuthenticationError::InvalidClaims);
        }
        if token_data.claims.iat > token_data.claims.exp {
            tracing::warn!(issuer = %safe_issuer, "Rejecting token where iat exceeds exp");
            return Err(AuthenticationError::InvalidClaims);
        }
        let lifetime = token_data.claims.exp - token_data.claims.iat;
        if lifetime > max_lifetime {
            tracing::warn!(
                issuer = %safe_issuer,
                lifetime_secs = lifetime,
                max_lifetime_secs = max_lifetime,
                "Rejecting token exceeding maximum lifetime"
            );
            return Err(AuthenticationError::InvalidClaims);
        }
    }

    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::test_utils::test_app_state;
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        extract::Request,
        http::{StatusCode, header},
        routing::get,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tower::ServiceExt;

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
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#
            .as_bytes()
            .to_vec(),
        )
        .unwrap()
    }

    fn now_secs() -> u64 {
        time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
    }

    fn test_encoding_key() -> EncodingKey {
        EncodingKey::from_ec_pem(test_ec_private_pem().as_bytes()).unwrap()
    }

    fn create_test_token(issuer: &str, secret: &EncodingKey, alg: Algorithm) -> String {
        let now = now_secs();
        let claims = Claims {
            iss: issuer.to_string(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            aud: None,
        };
        encode(&Header::new(alg), &claims, secret).unwrap()
    }

    fn create_test_token_with_claims(
        issuer: &str,
        secret: &EncodingKey,
        alg: Algorithm,
        exp: u64,
        iat: u64,
        nbf: Option<u64>,
        aud: Option<Audience>,
    ) -> String {
        let claims = Claims {
            iss: issuer.to_string(),
            exp,
            iat,
            nbf,
            aud,
        };
        encode(&Header::new(alg), &claims, secret).unwrap()
    }

    fn bearer_request(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn register_test_issuer(state: &AppState) {
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();
    }

    /// Build a router with `test-issuer` registered and the auth policy tuned by
    /// `configure`, returning the router and the matching ES256 encoding key.
    async fn setup_with(configure: impl FnOnce(&mut AppState)) -> (Router, EncodingKey) {
        let mut state = test_app_state(None).await;
        configure(&mut state);
        register_test_issuer(&state).await;
        let app = create_test_router(state);
        (app, test_encoding_key())
    }

    /// Build an authenticated router for a token signed with `wrong_pem`, used to
    /// exercise signature mismatches against a registered issuer.
    async fn setup_with_wrong_key(wrong_pem: &str) -> (Router, EncodingKey) {
        let state = test_app_state(None).await;
        register_test_issuer(&state).await;
        let app = create_test_router(state);
        (app, EncodingKey::from_ec_pem(wrong_pem.as_bytes()).unwrap())
    }

    async fn assert_ok(app: Router, token: &str) {
        let response = app.oneshot(bearer_request(token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn assert_unauthorized_without_claim_leak(app: Router, token: &str) {
        let response = app.oneshot(bearer_request(token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // The body must be generic and must not disclose which claim failed,
        // any token details, or library error messages (e.g. ExpiredSignature).
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            !body.contains("exp")
                && !body.contains("iat")
                && !body.contains("nbf")
                && !body.contains("aud")
                && !body.contains("signature")
                && !body.contains("ExpiredSignature")
                && !body.contains("ImmatureSignature"),
            "Response must not disclose claim details, got: {body}"
        );

        // Assert the actual wire contract rather than substring absence, so a
        // regression that changes the code/message is caught even if no detail
        // leaks.
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "invalid_token");
        assert_eq!(json["error_description"], "Token is invalid");
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let app = create_test_router(test_app_state(None).await);
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let app = create_test_router(test_app_state(None).await);
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Basic invalid_token")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let app = create_test_router(test_app_state(None).await);
        let response = app
            .oneshot(bearer_request("invalid_jwt_token"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_issuer_not_found_in_database() {
        let app = create_test_router(test_app_state(None).await);
        let token = create_test_token(
            "unregistered-issuer",
            &test_encoding_key(),
            Algorithm::ES256,
        );
        // A token from an unregistered issuer must be indistinguishable from an
        // invalid token (no enumeration oracle).
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let (app, key) = setup_with(|_| {}).await;
        let token = create_test_token("test-issuer", &key, Algorithm::ES256);
        let response = app.oneshot(bearer_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), "Ok");
    }

    #[tokio::test]
    async fn test_token_verification_failure_wrong_key() {
        let wrong_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi\najH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2\n7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5\n-----END PRIVATE KEY-----";
        let (app, wrong_key) = setup_with_wrong_key(wrong_pem).await;
        let token = create_test_token("test-issuer", &wrong_key, Algorithm::ES256);
        // A token signed with the wrong key must surface the same non-disclosing
        // invalid_token response as any other signature/claim failure.
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now - 3600,
            now - 7200,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_request_extension_contains_issuer() {
        let private_pem = test_ec_private_pem();
        let state = test_app_state(None).await;
        register_test_issuer(&state).await;

        async fn extension_test_handler(Extension(issuer): Extension<String>) -> String {
            assert_eq!(issuer, "test-issuer");
            issuer
        }

        let app = Router::new()
            .route("/test", get(extension_test_handler))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state);

        let token = create_test_token(
            "test-issuer",
            &EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
            Algorithm::ES256,
        );
        let response = app.oneshot(bearer_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), "test-issuer");
    }

    #[tokio::test]
    async fn test_missing_iat_claim_rejected() {
        let (app, key) = setup_with(|_| {}).await;
        // Build a token signed with the registered key but without `iat`.
        let token = encode(
            &Header::new(Algorithm::ES256),
            &serde_json::json!({ "iss": "test-issuer", "exp": now_secs() + 3600 }),
            &key,
        )
        .unwrap();
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_missing_exp_claim_rejected() {
        let (app, key) = setup_with(|_| {}).await;
        let token = encode(
            &Header::new(Algorithm::ES256),
            &serde_json::json!({ "iss": "test-issuer", "iat": now_secs() }),
            &key,
        )
        .unwrap();
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_not_yet_valid_token_with_future_nbf_rejected() {
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        // `nbf` in the future beyond leeway makes the token not yet valid.
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 7200,
            now,
            Some(now + 3600),
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_too_long_lived_token_rejected() {
        let (app, key) = setup_with(|state| state.auth.max_token_lifetime_secs = Some(600)).await;
        let now = now_secs();
        // Lifetime exp - iat = 3600s exceeds the 600s configured bound.
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_audience_mismatch_rejected() {
        let (app, key) =
            setup_with(|state| state.auth.expected_audience = Some("expected-aud".to_string()))
                .await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            Some(Audience::One("wrong-aud".to_string())),
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_matching_audience_accepted() {
        let (app, key) =
            setup_with(|state| state.auth.expected_audience = Some("expected-aud".to_string()))
                .await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            Some(Audience::One("expected-aud".to_string())),
        );
        assert_ok(app, &token).await;
    }

    #[tokio::test]
    async fn test_audience_array_containing_expected_accepted() {
        let (app, key) =
            setup_with(|state| state.auth.expected_audience = Some("expected-aud".to_string()))
                .await;
        let now = now_secs();
        // RFC 7519 §4.1.3 permits `aud` to be a JSON array of strings.
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            Some(Audience::Many(vec![
                "other-aud".into(),
                "expected-aud".into(),
            ])),
        );
        assert_ok(app, &token).await;
    }

    #[tokio::test]
    async fn test_audience_array_without_expected_rejected() {
        let (app, key) =
            setup_with(|state| state.auth.expected_audience = Some("expected-aud".to_string()))
                .await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            Some(Audience::Many(vec!["other-aud".into(), "wrong-aud".into()])),
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_iat_after_exp_rejected() {
        let (app, key) = setup_with(|state| state.auth.max_token_lifetime_secs = Some(600)).await;
        let now = now_secs();
        // `iat` (now + 7200) exceeds `exp` (now); previously the saturating
        // subtraction produced 0 and bypassed the max-lifetime check.
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now,
            now + 7200,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_omitted_aud_rejected_when_expected_audience_set() {
        // Regression: `set_audience` alone does not make `aud` required, so a
        // token with no `aud` claim at all previously slipped through as 200 OK.
        let (app, key) =
            setup_with(|state| state.auth.expected_audience = Some("expected-aud".to_string()))
                .await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_aud_claim_accepted_when_expected_audience_not_configured() {
        // `aud` is optional when `expected_audience` is unset: a token that
        // carries an `aud` claim must still be accepted and not validated.
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            Some(Audience::One("any-aud".to_string())),
        );
        assert_ok(app, &token).await;
    }

    #[tokio::test]
    async fn test_future_iat_rejected() {
        // `iat` is issuer-controlled and, by design, not compared to the server
        // clock by jsonwebtoken; reject tokens not yet valid beyond leeway.
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        // iat far in the future (next day), exp even further out.
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 100_060,
            now + 100_000,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_max_lifetime_anchored_to_server_clock() {
        // Regression: exp - iat alone was bypassable by an attacker choosing iat.
        // A token valid ~28h under a 60s policy previously returned 200 OK
        // (iat = now + 100_000, exp = now + 100_060). The absolute exp bound
        // against now + max_lifetime + leeway must reject it.
        let (app, key) = setup_with(|state| state.auth.max_token_lifetime_secs = Some(60)).await;
        let now = now_secs();
        let token = create_test_token_with_claims(
            "test-issuer",
            &key,
            Algorithm::ES256,
            now + 100_060,
            now + 100_000,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_oversized_issuer_rejected() {
        // The unverified `iss` is bounded before being used as a DB lookup key
        // or logged, so an attacker cannot inject oversized input or forge log
        // lines.
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        let big_issuer = "x".repeat(MAX_ISSUER_LEN + 1);
        let token = create_test_token_with_claims(
            &big_issuer,
            &key,
            Algorithm::ES256,
            now + 3600,
            now,
            None,
            None,
        );
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_fractional_numeric_date_accepted() {
        // RFC 7519 §2 NumericDate may be non-integer (e.g. Python time.time()).
        // Deserialization must coerce rather than fail as an opaque 401.
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        let claims = serde_json::json!({
            "iss": "test-issuer",
            "exp": (now + 3600) as f64,
            "iat": now as f64,
        });
        let token = encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap();
        assert_ok(app, &token).await;
    }

    #[tokio::test]
    async fn test_non_string_aud_rejected() {
        // `aud: 42` / `aud: {}` must not be silently accepted by a too-permissive
        // claim type; it should fail deserialization as a generic 401.
        let (app, key) = setup_with(|_| {}).await;
        let now = now_secs();
        let claims = serde_json::json!({
            "iss": "test-issuer",
            "exp": now + 3600,
            "iat": now,
            "aud": 42,
        });
        let token = encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap();
        assert_unauthorized_without_claim_leak(app, &token).await;
    }

    #[tokio::test]
    async fn test_oct_key_rejected_at_registration() {
        // An `oct` (shared-secret) key is rejected at registration with a 400
        // `invalid_public_jwk`, since POST /credentials is unauthenticated and
        // an HMAC key would otherwise be accepted but permanently unusable for
        // management token verification.
        let result = crate::domain::models::credential::PublicJwk::try_new(
            br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#.to_vec(),
        );
        let err = result.expect_err("oct key must be rejected");
        assert!(
            err.to_string().contains("oct"),
            "error should mention the rejected key type: {err}"
        );
    }

    #[tokio::test]
    async fn test_hmac_key_rejected_by_middleware_defense_in_depth() {
        // Defense-in-depth: even if an `oct` (HMAC) key somehow exists in the
        // credential store (e.g. registered before the registration guard), the
        // middleware rejects it. The credential is constructed directly to
        // bypass `PublicJwk::try_new`, which now rejects oct keys at the API.
        let state = test_app_state(None).await;
        let secret_jwk = crate::domain::models::credential::PublicJwk(
            br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#.to_vec(),
        );
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("hmac-issuer".into()),
                public_key: secret_jwk,
            })
            .await
            .unwrap();
        let app = create_test_router(state);

        // Sign an HS256 token with the shared secret.
        let secret = EncodingKey::from_secret(b"GawgguFyGrWKav7AX4VKUg");
        let now = now_secs();
        let claims = serde_json::json!({
            "iss": "hmac-issuer",
            "exp": now + 3600,
            "iat": now,
        });
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &secret).unwrap();

        // The HMAC rejection folds into the generic non-disclosing invalid_token
        // (it must not reveal that an HMAC/oct key is in use).
        assert_unauthorized_without_claim_leak(app, &token).await;
    }
}
