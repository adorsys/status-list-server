use axum::{
    Extension, Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};

use crate::domain::models::hosted_issuer::{HostedIssuerError, HostedIssuerState};
use crate::server::{AppState, auth::AuthenticatedAdmin, error::ApiError};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStateInput {
    Active,
    Suspended,
}

#[derive(Deserialize)]
pub struct ChangeIssuerState {
    pub state: IssuerStateInput,
}

#[derive(Serialize)]
pub struct IssuerStateOutput {
    pub issuer_id: String,
    pub state: &'static str,
    pub version: u64,
}

#[derive(Serialize)]
pub struct RevokedKeyOutput {
    pub issuer_id: String,
    pub kid: String,
    pub state: &'static str,
}

fn lifecycle_error(error: HostedIssuerError) -> ApiError {
    match error {
        HostedIssuerError::NotFound => {
            ApiError::not_found("issuer_not_found", "Hosted issuer or key was not found")
        }
        HostedIssuerError::InvalidExpiry(_) => {
            ApiError::unprocessable("invalid_expiry", "An expired issuer cannot be reactivated")
        }
        HostedIssuerError::Contention { .. } => ApiError::write_contention(),
        other => {
            tracing::error!(error = %other, "hosted lifecycle write failed");
            ApiError::internal("hosted lifecycle write failed")
        }
    }
}

pub async fn change_issuer_state(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path(issuer_id): Path<String>,
    Json(input): Json<ChangeIssuerState>,
) -> Result<Json<IssuerStateOutput>, ApiError> {
    let service = state.hosted_lifecycle_service.as_ref().ok_or_else(|| {
        ApiError::not_found(
            "hosted_profile_required",
            "Hosted issuer lifecycle is unavailable",
        )
    })?;
    let requested = match input.state {
        IssuerStateInput::Active => HostedIssuerState::Active,
        IssuerStateInput::Suspended => HostedIssuerState::Suspended,
    };
    let issuer = service
        .set_issuer_state(&issuer_id, requested, &admin.id)
        .await
        .map_err(lifecycle_error)?;
    Ok(Json(IssuerStateOutput {
        issuer_id: issuer.id,
        state: if issuer.state == HostedIssuerState::Active {
            "active"
        } else {
            "suspended"
        },
        version: issuer.version,
    }))
}

pub async fn revoke_hosted_key(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path((issuer_id, kid)): Path<(String, String)>,
) -> Result<Json<RevokedKeyOutput>, ApiError> {
    let service = state.hosted_lifecycle_service.as_ref().ok_or_else(|| {
        ApiError::not_found(
            "hosted_profile_required",
            "Hosted issuer lifecycle is unavailable",
        )
    })?;
    let key = service
        .revoke_key(&issuer_id, &kid, &admin.id)
        .await
        .map_err(lifecycle_error)?;
    Ok(Json(RevokedKeyOutput {
        issuer_id: key.issuer_id,
        kid: key.kid,
        state: "revoked",
    }))
}
