use std::{fmt::Debug, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::Value;

use crate::{
    model::{Status, StatusList, StatusListToken, StatusUpdate},
    utils::state::{AppState, AppStateRepository},
};

use super::{
    constants::{STATUS_LISTS_HEADER_CWT, STATUS_LISTS_HEADER_JWT},
    error::StatusListError,
};

pub trait StatusListTokenExt {
    fn new(
        list_id: String,
        exp: Option<i32>,
        iat: i32,
        status_list: StatusList,
        sub: String,
        ttl: Option<String>,
    ) -> Self;
}

impl StatusListTokenExt for StatusListToken {
    fn new(
        list_id: String,
        exp: Option<i32>,
        iat: i32,
        status_list: StatusList,
        sub: String,
        ttl: Option<String>,
    ) -> Self {
        Self {
            list_id,
            exp,
            iat,
            status_list: serde_json::to_value(status_list).unwrap(),
            sub,
            ttl,
        }
    }
}

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let repo = &state.status_list_token_repository;

    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // build the token depending on the accept header
    match accept {
        Some(accept) if accept.contains(STATUS_LISTS_HEADER_JWT) => {
            build_status_list_token(STATUS_LISTS_HEADER_JWT, &list_id, repo).await
        }
        Some(accept) if accept.contains(STATUS_LISTS_HEADER_CWT) => {
            build_status_list_token(STATUS_LISTS_HEADER_CWT, &list_id, repo).await
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
        None =>
        // assume jwt by default if no accept header is provided
        {
            build_status_list_token(STATUS_LISTS_HEADER_JWT, &list_id, repo).await
        }
    }
}

async fn build_status_list_token(
    accept: &str,
    list_id: &str,
    repo: &AppStateRepository,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    // Get status list claims from database
    let status_claims = repo
        .find_one_by(list_id.to_string())
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    let status_list = status_claims.status_list;

    if STATUS_LISTS_HEADER_JWT == accept {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, accept)],
            Json(status_list),
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, accept)],
            // TODO : implement CWT serialization
            String::new(),
        )
            .into_response())
    }
}

fn issue_jwt(status_list: StatusList) -> Result<StatusListToken, StatusListError> {
    Err(StatusListError::UnsupportedBits)
}

pub async fn update_statuslist(
    State(appstate): State<Arc<AppState>>,
    Path(list_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let updates = match body
        .as_object()
        .and_then(|body| body.get("updates"))
        .and_then(|statuslist| statuslist.as_array())
    {
        Some(updates) => updates,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
            )
                .into_response();
        }
    };

    let updates_json = match serde_json::to_vec(updates) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to serialize updates: {e}");
            return (StatusCode::BAD_REQUEST, "Failed to serialize request body").into_response();
        }
    };

    let updates: Vec<StatusUpdate> = match serde_json::from_slice(&updates_json) {
        Ok(updates) => updates,
        Err(e) => {
            tracing::error!("Malformed request body: {e}");
            return (
                StatusCode::BAD_REQUEST,
                StatusListError::MalformedBody(
                    "Request body must contain a valid 'updates' array".to_string(),
                ),
            )
                .into_response();
        }
    };

    let store = &appstate.status_list_token_repository;

    let status_list_token = match store.find_one_by(list_id.clone()).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Find error: {:?}", e);
            return (
                StatusCode::NOT_FOUND,
                StatusListError::StatusListNotFound.to_string(),
            )
                .into_response();
        }
    };
    if let Some(status_list_token) = status_list_token {
        let lst: StatusList =
            serde_json::from_value(status_list_token.status_list.clone()).unwrap();
        let updated_lst = match update_status(&lst.lst, updates) {
            Ok(updated_lst) => updated_lst,
            Err(e) => {
                tracing::error!("Status update failed: {:?}", e);
                return match e {
                    StatusListError::InvalidIndex => {
                        (StatusCode::BAD_REQUEST, "Invalid index").into_response()
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        StatusListError::UpdateFailed.to_string(),
                    )
                        .into_response(),
                };
            }
        };

        let status_list = StatusList {
            bits: lst.bits,
            lst: updated_lst,
        };

        let statuslisttoken = StatusListToken::new(
            list_id.clone(),
            status_list_token.exp,
            status_list_token.iat,
            status_list,
            status_list_token.sub.clone(),
            status_list_token.ttl.clone(),
        );

        match store.update_one(list_id.clone(), statuslisttoken).await {
            Ok(true) => StatusCode::ACCEPTED.into_response(),
            Ok(false) => {
                tracing::error!("Failed to update status list");
                (
                    StatusCode::BAD_REQUEST,
                    StatusListError::UpdateFailed.to_string(),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Update error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Status list not found").into_response()
    }
}

fn encode_lst(bits: Vec<u8>) -> String {
    base64url::encode(
        bits.iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    )
}

fn update_status(lst: &str, updates: Vec<StatusUpdate>) -> Result<String, StatusListError> {
    let mut decoded_lst =
        base64url::decode(lst).map_err(|e| StatusListError::Generic(e.to_string()))?;

    for update in updates {
        let index = update.index as usize;
        if index >= decoded_lst.len() {
            return Err(StatusListError::InvalidIndex);
        }

        decoded_lst[index] = match update.status {
            Status::VALID => 0,
            Status::INVALID => 1,
            Status::SUSPENDED => 2,
            Status::APPLICATIONSPECIFIC => 3,
        };
    }

    Ok(encode_lst(decoded_lst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, StatusList, StatusListToken},
        utils::state::AppState,
    };
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::{self, HeaderMap, StatusCode},
        Json,
    };
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_get_status_list_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let status_list_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            status_list.clone(),
            "test_subject".to_string(),
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![
                    status_list_token,
                ]])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(State(app_state), Path("test_list".to_string()), headers)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body,
            json!({
                "bits": 8,
                "lst": encode_lst(vec![0, 0, 0])
            })
        );
    }

    #[tokio::test]
    async fn test_get_status_list_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );

        let app_state = AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(State(app_state), Path("test_list".to_string()), headers)
            .await
            .unwrap_err();

        assert_eq!(response, StatusListError::StatusListNotFound);
    }

    #[tokio::test]
    async fn test_update_statuslist_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let initial_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let existing_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            initial_status_list.clone(),
            "test_subject".to_string(),
            None,
        );
        let updated_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 1, 0]), // After update: index 1 set to INVALID
        };
        let updated_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            updated_status_list,
            "test_subject".to_string(),
            None,
        );
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![existing_token.clone()],
                    vec![existing_token],
                    vec![updated_token],
                ])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
        });

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state),
            Path("test_list".to_string()),
            Json(update_body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_update_statuslist_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
        });

        let update_body = json!({
            "updates": [
                {"index": 1, "status": "INVALID"}
            ]
        });

        let response = update_statuslist(
            State(app_state),
            Path("test_list".to_string()),
            Json(update_body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
