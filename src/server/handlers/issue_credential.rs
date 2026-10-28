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

/// Handle GET /credentials: the aggregation ID and URI provisioned for the
/// authenticated issuer.
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
    use crate::test_utils::{authenticated_issuer, test_app_state};
    use axum::extract::State;
    use std::sync::Arc;

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
                "keys": [{"kid": "test-key", "alg": "ES256", "jwk": {
                    "kty": "EC", "crv": "P-256",
                    "x": "4R_68o1GpW2SvRroSJnCqWzcEX0JRnK3fQf9Rl4Jqig",
                    "y": "D0wUeShMhjtWIGilbnCeboV-wkiCUmYPXVjezCml1Uk"
                }}],
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
        assert_eq!(
            registration.aggregation_uri.as_deref(),
            Some(
                format!("https://statuslist.example.com/api/v1/aggregation/{aggregation_id}")
                    .as_str()
            )
        );
    }
}
