use std::fmt::Debug;
use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::{header, HeaderMap},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing;

use crate::{
    model::{StatusList, StatusListToken},
    utils::state::AppState,
    web::handlers::status_list::{
        constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
        error::StatusListError,
        handler::build_status_list_token,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusListAggregationRequest {
    pub list_ids: Vec<String>,
}

#[allow(dead_code)]
fn encode_lst(bits: Vec<u8>) -> String {
    base64url::encode(
        bits.iter()
            .flat_map(|&n| n.to_be_bytes())
            .collect::<Vec<u8>>(),
    )
}

pub async fn aggregate_status_lists(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<StatusListAggregationRequest>,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    // Validate accept header
    let accept = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT, // Default to JWT if no accept header
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept
        }
        Some(_) => return Err(StatusListError::InvalidAcceptHeader),
    };

    // Get all status lists from the database
    let mut status_lists = Vec::new();
    for list_id in request.list_ids {
        let status_list = state
            .status_list_token_repository
            .find_one_by(list_id.clone())
            .await
            .map_err(|err| {
                tracing::error!("Failed to get status list {list_id} from database: {err:?}");
                StatusListError::InternalServerError
            })?
            .ok_or(StatusListError::StatusListNotFound)?;
        status_lists.push(status_list);
    }

    // Aggregate the status lists
    let aggregated_list = aggregate_status_lists_impl(status_lists)?;

    // Create a new status list token for the aggregated list
    let _aggregated_token = StatusListToken::new(
        "aggregated".to_string(),
        None,
        chrono::Utc::now().timestamp(),
        aggregated_list,
        "aggregated".to_string(),
        None,
    );

    // Return the aggregated list in the requested format
    build_status_list_token(accept, &_aggregated_token, &state).await
}

fn aggregate_status_lists_impl(
    status_lists: Vec<StatusListToken>,
) -> Result<StatusList, StatusListError> {
    if status_lists.is_empty() {
        return Err(StatusListError::Generic(
            "No status lists provided".to_string(),
        ));
    }

    // Get the maximum bits value from all lists
    let max_bits = status_lists
        .iter()
        .map(|list| list.status_list.bits)
        .max()
        .unwrap_or(0);

    // Combine all status lists
    let mut combined_lst = String::new();
    for list in status_lists {
        combined_lst.push_str(&list.status_list.lst);
    }

    Ok(StatusList {
        bits: max_bits,
        lst: combined_lst,
    })
}

pub trait StatusListTokenExt {
    fn new(
        list_id: String,
        exp: Option<i64>,
        iat: i64,
        status_list: StatusList,
        sub: String,
        ttl: Option<i64>,
    ) -> Self;
}

impl StatusListTokenExt for StatusListToken {
    fn new(
        list_id: String,
        exp: Option<i64>,
        iat: i64,
        status_list: StatusList,
        sub: String,
        ttl: Option<i64>,
    ) -> Self {
        Self {
            list_id,
            exp,
            iat,
            status_list,
            sub,
            ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::queries::SeaOrmStore,
        model::{status_list_tokens, StatusListToken},
        utils::keygen::Keypair,
    };
    use axum::http::StatusCode;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;

    // Helper to create a test request payload
    fn create_test_request(list_ids: Vec<String>) -> StatusListAggregationRequest {
        StatusListAggregationRequest { list_ids }
    }

    // Helper to generate a test server key
    fn server_key() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[tokio::test]
    async fn test_aggregate_status_lists_success() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let list_id1 = "list1";
        let list_id2 = "list2";
        let request = create_test_request(vec![list_id1.to_string(), list_id2.to_string()]);

        let status_list1 = StatusListToken::new(
            list_id1.to_string(),
            None,
            chrono::Utc::now().timestamp(),
            StatusList {
                bits: 2,
                lst: "abc".to_string(),
            },
            "issuer1".to_string(),
            None,
        );

        let status_list2 = StatusListToken::new(
            list_id2.to_string(),
            None,
            chrono::Utc::now().timestamp(),
            StatusList {
                bits: 2,
                lst: "def".to_string(),
            },
            "issuer2".to_string(),
            None,
        );

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![status_list1.clone()], // find_one_by for list1
                    vec![status_list2.clone()], // find_one_by for list2
                ])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_aggregate_status_lists_not_found() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let list_id1 = "list1";
        let list_id2 = "list2";
        let request = create_test_request(vec![list_id1.to_string(), list_id2.to_string()]);

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![], // find_one_by for list1 returns None
                ])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_aggregate_status_lists_invalid_accept_header() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let list_id1 = "list1";
        let list_id2 = "list2";
        let request = create_test_request(vec![list_id1.to_string(), list_id2.to_string()]);

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![], // find_one_by for list1 returns None
                ])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "invalid/format".parse().unwrap());
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn test_aggregate_status_lists_empty_list() {
        let mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let request = create_test_request(vec![]);

        let db_conn = Arc::new(
            mock_db
                .append_query_results::<status_list_tokens::Model, Vec<_>, _>(vec![
                    vec![], // find_one_by returns None
                ])
                .into_connection(),
        );

        let app_state = Arc::new(AppState {
            credential_repository: Arc::new(SeaOrmStore::new(db_conn.clone())),
            status_list_token_repository: Arc::new(SeaOrmStore::new(db_conn)),
            server_key: Arc::new(server_key()),
        });

        let headers = HeaderMap::new();
        let response = aggregate_status_lists(State(app_state), headers, Json(request))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_statuslist_success() {
        let _mock_db = MockDatabase::new(DatabaseBackend::Postgres);
        let initial_status_list = StatusList {
            bits: 8,
            lst: encode_lst(vec![0, 0, 0]),
        };
        let _existing_token = StatusListToken::new(
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
        let _updated_token = StatusListToken::new(
            "test_list".to_string(),
            None,
            1234567890,
            updated_status_list,
            "test_subject".to_string(),
            None,
        );
    }
}
