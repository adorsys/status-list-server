use std::{fmt::Debug, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use serde_json::Value;
use std::io::{Read, Write};

use crate::{
    model::{Status, StatusList, StatusListToken, StatusUpdate},
    utils::state::AppState,
};

use super::{constants::STATUS_LISTS_HEADER_JWT, error::StatusListError};

// Return the specified status list token
pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug, StatusListError> {
    // check the persistence layer
    let repo = state.repository.as_ref().ok_or_else(|| {
        tracing::error!("Repository is unavailable");
        StatusListError::InternalServerError
    })?;

    // Validate accept header
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(STATUS_LISTS_HEADER_JWT);

    if !accept.contains(STATUS_LISTS_HEADER_JWT) {
        return Err(StatusListError::InvalidAcceptHeader);
    }

    // Get status list claims from database
    let status_claims = repo
        .status_list_token_repository
        .find_one_by(list_id.to_string())
        .await
        .map_err(|err| {
            tracing::error!("Failed to get status list {list_id} from database: {err:?}");
            StatusListError::InternalServerError
        })?
        .ok_or(StatusListError::StatusListNotFound)?;

    // TODO : add function to construct the status list token from this status list before sending it out
    let status_list = status_claims.status_list;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, STATUS_LISTS_HEADER_JWT)],
        Json(status_list),
    )
        .into_response())
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

    // Ensure repository exists
    let store = match &appstate.repository {
        Some(store) => store,
        None => {
            tracing::error!("Repository is unavailable");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Fetch the status list token from the database
    let status_list_token = match store
        .status_list_token_repository
        .find_one_by(list_id.clone())
        .await
    {
        Ok(token) => token,
        Err(_) => {
            tracing::error!("Status list not found: {}", list_id);
            return (
                StatusCode::NOT_FOUND,
                StatusListError::StatusListNotFound.to_string(),
            )
                .into_response();
        }
    };

    if let Some(status_list_token) = status_list_token {
        let lst = status_list_token.status_list.lst.clone();

        // Apply updates

        let updated_lst = match update_status(&lst, updates) {
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

        // Construct the new status list token
        let status_list = StatusList {
            bits: status_list_token.status_list.bits,
            lst: updated_lst,
        };

        let list_id = status_list_token.list_id;
        let statuslisttoken = StatusListToken::new(
            list_id.clone(),
            status_list_token.exp,
            status_list_token.iat,
            status_list,
            status_list_token.sub.clone(),
            status_list_token.ttl.clone(),
        );

        // Store updated list in the database
        match store
            .status_list_token_repository
            .update_one(list_id.clone(), statuslisttoken)
            .await
        {
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
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "Status list not found").into_response()
    }
}

pub fn update_status(lst: &str, updates: Vec<StatusUpdate>) -> Result<String, StatusError> {
    // bas
    let decoded_lst = base64url::decode(lst).map_err(|e| StatusError::Generic(e.to_string()))?;

    // decompressed byte array
    let mut decompressed_lst = ZlibDecoder::new(&*decoded_lst);
    let mut decompressed_array = vec![];
    decompressed_lst
        .read_to_end(&mut decompressed_array)
        .map_err(|_| StatusError::Generic("could not decompressed lst".to_string()))?;

    for update in updates {
        let index = update.index as usize;
        if index >= decompressed_array.len() * 8 {
            return Err(StatusError::InvalidIndex);
        }

        let byte_index = index / 8;
        let bit_index = index % 8;
        let mask = 1 << bit_index;

        match update.status {
            Status::VALID => {
                decompressed_array[byte_index] &= !mask;
            }
            Status::INVALID => {
                decompressed_array[byte_index] |= mask;
            }

            _ => {
                tracing::warn!("Unsupported status variant: {:?}", update.status);
                return Err(StatusError::MalformedBody);
            }
        }
    }

    // compress the updated status
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&decompressed_array)
        .map_err(|_| StatusError::Generic("could not compress lst".to_string()))?;
    let encoded = encoder
        .finish()
        .map_err(|_| StatusError::Generic("failed to encode".to_string()))?;

    Ok(base64url::encode(encoded))
}

#[cfg(test)]
mod test {

    use super::*;
    use std::{
        collections::HashMap,
        io::{Read, Write},
        sync::{Arc, RwLock},
    };

    use axum::{
        body::Body,
        extract::Request,
        routing::{get, put},
        Router,
    };
    use base64url::encode;
    use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
    use hyper::StatusCode;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::{
        model::{Credentials, StatusList, StatusListToken},
        test_resources::setup::test_setup,
        utils::state::AppState,
    };

    pub fn setup() -> (AppState, Arc<RwLock<HashMap<String, StatusListToken>>>) {
        let mut mock_statustk_repo = HashMap::new();
        let mock_credential_repo: HashMap<String, Credentials> = HashMap::new();

        let status = vec![0b11111111, 0b01101110];
        // compress status
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&status).unwrap();
        let compressed_status = encoder.finish().unwrap();

        // encode status lst
        let lst = encode(compressed_status);

        let list_id = "list_id".to_string();
        let existing_status_list = StatusList { bits: 1, lst };

        let existing_token = StatusListToken::new(
            list_id.clone(),
            Some(123456789),
            123456000,
            existing_status_list,
            "test_sub".to_string(),
            Some("3600".to_string()),
        );

        // store the token
        mock_statustk_repo.insert(list_id.clone(), existing_token);
        let shared_statustk_repo = Arc::new(RwLock::new(mock_statustk_repo));

        let appstate = test_setup(
            Arc::new(RwLock::new(mock_credential_repo)),
            shared_statustk_repo.clone(),
        );

        (appstate, shared_statustk_repo)
    }

    #[tokio::test]
    async fn test_update_statuslist() {
        let appstate = setup();

        let app = Router::new()
            .route("/statuslist/{issuer}", put(update_statuslist))
            .with_state(Arc::new(appstate.0));

        // JSON request body
        let body = json!({
        "updates": [
            { "index": 1, "status": "VALID" },
            { "index": 8, "status": "VALID" }
            ]
        });
        let updated_lst = vec![0b11111101, 0b01101110];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&updated_lst).unwrap();
        let compressed_status = encoder.finish().unwrap();

        let expected_lst = encode(compressed_status);

        let list_id = "list_id".to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/statuslist/{}", list_id))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        // Send request
        let response = app.oneshot(request).await.unwrap();

        // Check response status
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let shared_lst = appstate
            .1
            .read()
            .unwrap()
            .get(&list_id)
            .unwrap()
            .status_list
            .lst
            .clone();

        // decode lst
        let decoded_lst = base64url::decode(&shared_lst).unwrap();

        let mut decompressed_lst = ZlibDecoder::new(&*decoded_lst);
        let mut decompressed_array = vec![];
        decompressed_lst
            .read_to_end(&mut decompressed_array)
            .unwrap();

        // assert the lst has been updated
        assert_eq!(shared_lst, expected_lst);
    }

    #[tokio::test]
    async fn test_malformed_body() {
        let appstate = setup();

        let app = Router::new()
            .route("/statuslist/{issuer}", put(update_statuslist))
            .with_state(Arc::new(appstate.0));

        // JSON request body
        let bad_body = json!({
        "updates": [
            { "index": 1, "status": "VALID" },
            { "index": 3, "status": "UNKNOWSTATUS" }
            ]
        });

        let list_id = "list_id".to_string();
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/statuslist/{}", list_id))
            .header("Content-Type", "application/json")
            .body(Body::from(bad_body.to_string()))
            .unwrap();

        // Send request
        let response = app.oneshot(request).await.unwrap();

        // Check response status
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_status_list_repo_not_set() {
        let appstate = AppState { repository: None };
        let app = Router::new()
            .route("/statuslists/{id}", get(get_status_list))
            .with_state(appstate.clone());

        let headers = HeaderMap::new();

        let response =
            get_status_list(State(appstate), Path("test_list".to_string()), headers).await;
        assert_eq!(response.unwrap_err(), StatusListError::InternalServerError);

        let list_id = "list_id".to_string();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/statuslists/{list_id}"))
            .header("Content-Type", "application/json")
            .body(Body::from(""))
            .unwrap();

        // We expect a 500 error because the repository is not set
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_status_list_invalid_accept_header() {
        let appstate = setup();

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        // The valid accept header is "application/statuslist+jwt"
        let response = get_status_list(
            State(appstate.clone().0),
            Path("list_id".to_string()),
            headers,
        )
        .await;
        assert_eq!(response.unwrap_err(), StatusListError::InvalidAcceptHeader);

        let app = Router::new()
            .route("/statuslists/{id}", get(get_status_list))
            .with_state(appstate.0);

        let list_id = "list_id".to_string();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/statuslists/{list_id}"))
            .header(header::ACCEPT, "application/json")
            .body(Body::from(""))
            .unwrap();

        // We should get a 400 because the accept header is invalid
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_status_list_not_found() {
        let appstate = setup();

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, STATUS_LISTS_HEADER_JWT.parse().unwrap());

        let response = get_status_list(
            State(appstate.clone().0),
            Path("invalid_id".to_string()),
            headers,
        )
        .await;
        assert_eq!(response.unwrap_err(), StatusListError::StatusListNotFound);

        let app = Router::new()
            .route("/statuslists/{id}", get(get_status_list))
            .with_state(appstate.0);

        let list_id = "invalid_id".to_string();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/statuslists/{list_id}"))
            .header(header::ACCEPT, STATUS_LISTS_HEADER_JWT)
            .body(Body::from(""))
            .unwrap();

        // We should get a 404 because the status list with the given id does not exist
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_status_list_success() {
        let appstate = setup();

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, STATUS_LISTS_HEADER_JWT.parse().unwrap());

        let response = get_status_list(
            State(appstate.clone().0),
            Path("list_id".to_string()),
            headers,
        )
        .await;
        assert!(response.is_ok());

        let app = Router::new()
            .route("/statuslists/{id}", get(get_status_list))
            .with_state(appstate.0);

        let list_id = "list_id".to_string();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/statuslists/{list_id}"))
            .header(header::ACCEPT, STATUS_LISTS_HEADER_JWT)
            .body(Body::from(""))
            .unwrap();

        // We should get a 200 because the status list with the given id exists
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
