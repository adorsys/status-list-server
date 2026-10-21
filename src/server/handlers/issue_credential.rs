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

/// Handle GET /credentials: the calling issuer's aggregation ID and URI. The
/// registry preserves these values when migrating existing issuers.
#[tracing::instrument(skip_all, fields(issuer = %issuer), err(level = "info", Debug))]
pub async fn get_credential(
    State(state): State<AppState>,
    issuer: AuthenticatedIssuer,
) -> Result<Json<RegistrationResponse>, ApiError> {
    let registry_aggregation_id = issuer.aggregation_id();
    let issuer = issuer.into_issuer();
    let aggregation_id = match registry_aggregation_id
        .or_else(|| state.issuer_registry.issuer_aggregation_id(&issuer.0))
    {
        Some(aggregation_id) => aggregation_id,
        None => state
            .service
            .find_aggregation_id(&issuer)
            .await?
            .ok_or_else(|| {
                tracing::warn!(iss = %issuer.0, "Credential disappeared after authentication");
                AuthenticationError::InvalidToken.into_api_error()
            })?,
    };
    let aggregation_uri = state.aggregation_uri_for(&issuer, aggregation_id);
    Ok(Json(RegistrationResponse {
        issuer: issuer.0,
        aggregation_id,
        aggregation_uri,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::test_utils::{authenticated_issuer, register_issuer, test_app_state};
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };
    use std::{collections::HashSet, sync::Arc};

    fn test_jwk() -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-key",
                "alg": "ES256",
                "x": "4R_68o1GpW2SvRroSJnCqWzcEX0JRnK3fQf9Rl4Jqig",
                "y": "D0wUeShMhjtWIGilbnCeboV-wkiCUmYPXVjezCml1Uk"
            }
            "#,
        )
        .unwrap()
    }

    async fn register(app_state: AppState) -> RegistrationResponse {
        register_issuer(&app_state.service, "test_issuer").await;
        get_credential(State(app_state), authenticated_issuer("test_issuer"))
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn test_get_credential_returns_the_issuers_aggregation() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let registered = register(app_state.clone()).await;

        let Json(registration) =
            get_credential(State(app_state), authenticated_issuer("test_issuer"))
                .await
                .unwrap();
        assert_eq!(registration.issuer, "test_issuer");
        assert_eq!(registration.aggregation_id, registered.aggregation_id);
        assert_eq!(registration.aggregation_uri, registered.aggregation_uri);
    }

    #[tokio::test]
    async fn static_registry_issuer_gets_its_aggregation_without_a_database_credential() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let aggregation_id = uuid::Uuid::new_v4();
        let registry = serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "static-issuer",
                "aggregation_id": aggregation_id,
                "keys": [{"kid": "test-key", "alg": "ES256", "jwk": test_jwk()}],
            }],
            "admins": []
        }))
        .unwrap();
        app_state.set_issuer_registry(Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(&registry).unwrap(),
        ));

        let Json(registration) =
            get_credential(State(app_state), authenticated_issuer("static-issuer"))
                .await
                .unwrap();
        assert_eq!(registration.aggregation_id.0, aggregation_id);
        let expected_uri =
            format!("https://statuslist.example.com/api/v1/aggregation/{aggregation_id}");
        assert_eq!(
            registration.aggregation_uri.as_deref(),
            Some(expected_uri.as_str())
        );
    }

    #[tokio::test]
    async fn test_credentials_withhold_the_aggregation_uri_per_issuer() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        app_state.aggregation_withheld_from =
            Arc::new(HashSet::from([Issuer::from("test_issuer")]));
        let withheld = register(app_state.clone()).await;
        assert_eq!(withheld.aggregation_uri, None);
        let Json(registration) = get_credential(
            State(app_state.clone()),
            authenticated_issuer("test_issuer"),
        )
        .await
        .unwrap();
        assert_eq!(registration.aggregation_id, withheld.aggregation_id);
        assert_eq!(registration.aggregation_uri, None);

        let other_id = register_issuer(&app_state.service, "other_issuer").await;
        let Json(other) = get_credential(State(app_state), authenticated_issuer("other_issuer"))
            .await
            .unwrap();
        assert_eq!(
            other.aggregation_uri,
            Some(format!(
                "https://statuslist.example.com/api/v1/aggregation/{other_id}"
            ))
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
