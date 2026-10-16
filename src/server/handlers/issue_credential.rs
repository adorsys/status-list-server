use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    domain::models::credential::AggregationId,
    server::{
        AppState,
        auth::{AuthenticatedIssuer, errors::AuthenticationError},
        error::{ApiError, IntoApiError},
    },
};

/// Response body for GET /credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub issuer: String,
    pub aggregation_id: AggregationId,
    /// Present when the server advertises an aggregation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

/// Handle GET /credentials: the calling issuer's aggregation ID and URI.
#[tracing::instrument(skip_all, fields(issuer = %issuer), err(level = "info", Debug))]
pub async fn get_credential(
    State(state): State<AppState>,
    issuer: AuthenticatedIssuer,
) -> Result<Json<RegistrationResponse>, ApiError> {
    let issuer = issuer.into_issuer();
    let aggregation_id = state
        .service
        .find_aggregation_id(&issuer)
        .await?
        .ok_or_else(|| {
            tracing::warn!(iss = %issuer.0, "Credential disappeared after authentication");
            AuthenticationError::InvalidToken.into_api_error()
        })?;
    Ok(Json(RegistrationResponse {
        issuer: issuer.0,
        aggregation_id,
        aggregation_uri: state.aggregation_uri_for(aggregation_id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{authenticated_issuer, register_issuer, test_app_state};
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    #[tokio::test]
    async fn test_get_credential_returns_the_issuers_aggregation() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let aggregation_id = register_issuer(&app_state.service, "test_issuer").await;

        let Json(registration) =
            get_credential(State(app_state), authenticated_issuer("test_issuer"))
                .await
                .unwrap();
        assert_eq!(registration.issuer, "test_issuer");
        assert_eq!(registration.aggregation_id, aggregation_id);
        assert_eq!(
            registration.aggregation_uri.unwrap(),
            format!("https://statuslist.example.com/api/v1/aggregation/{aggregation_id}")
        );
    }

    #[tokio::test]
    async fn test_get_credential_for_an_unknown_issuer_is_invalid_token() {
        let app_state = test_app_state(None).await;
        let err = get_credential(State(app_state), authenticated_issuer("nobody"))
            .await
            .unwrap_err();
        let response = err.into_response();
        let expected = AuthenticationError::InvalidToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.status(), expected.status());
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            expected.headers()[header::WWW_AUTHENTICATE]
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            axum::body::to_bytes(expected.into_body(), usize::MAX)
                .await
                .unwrap()
        );
    }
}
