use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::Value;

/// YAML source of the OpenAPI 3.1 specification.
const OPENAPI_YAML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.yaml"));

#[derive(Debug)]
pub struct OpenApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for OpenApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}

impl From<serde_yaml::Error> for OpenApiError {
    fn from(err: serde_yaml::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Invalid OpenAPI spec: {err}"),
        }
    }
}

/// Serve the OpenAPI specification as JSON.
///
/// The YAML specification is embedded at build time and converted to JSON on the
/// fly so that the source of truth remains the human-readable `docs/openapi.yaml`
/// file while clients can consume it as `application/json`.
pub async fn openapi_json() -> Result<Json<Value>, OpenApiError> {
    let spec: Value = serde_yaml::from_str(OPENAPI_YAML)?;
    Ok(Json(spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_openapi_handler_returns_valid_json() {
        let Json(value) = openapi_json().await.unwrap();
        let obj = value
            .as_object()
            .expect("OpenAPI spec must be a JSON object");
        assert!(obj.contains_key("openapi"));
        assert!(obj.contains_key("info"));
        assert!(obj.contains_key("paths"));
    }
}
