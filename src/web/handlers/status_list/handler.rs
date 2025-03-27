use std::{fmt::Debug, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

use base64url::{decode, encode};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
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
        let bits = status_list_token.status_list.bits as usize;

        // Apply updates

        let updated_lst = match update_status(lst, updates, bits) {
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

pub fn update_status(
    lst: String,
    status_updates: Vec<StatusUpdate>,
    bits: usize,
) -> Result<String, StatusListError> {
    if status_updates.is_empty() {
        return Err(StatusListError::Generic(
            "No status updates provided".to_string(),
        ));
    }

    // Validate the 'bits' parameter
    if ![1, 2, 4, 8].contains(&bits) {
        return Err(StatusListError::UnsupportedBits);
    }

    // Decode the existing Base64-encoded status list
    let compressed_data = decode(&lst).map_err(|_| StatusListError::DecodeError)?;

    // Decompress the data using zlib
    let mut decoder = ZlibDecoder::new(&compressed_data[..]);
    let mut status_array = Vec::new();
    decoder
        .read_to_end(&mut status_array)
        .map_err(|e| StatusListError::DecompressionError(e.to_string()))?;

    // Determine the highest index in the updates to ensure the array is large enough
    let max_update_index = status_updates
        .iter()
        .map(|update| update.index)
        .max()
        .unwrap_or(0);
    if max_update_index < 0 {
        return Err(StatusListError::InvalidIndex);
    }

    let required_len = ((max_update_index as usize + 1) * bits + 7) / 8;
    if status_array.len() < required_len {
        status_array.resize(required_len, 0);
    }

    // Apply each status update
    for update in status_updates {
        if update.index < 0 {
            return Err(StatusListError::InvalidIndex);
        }
        let idx = update.index as usize;

        // Determine the bit position for the current index
        let bit_position = idx * bits;
        let byte_index = bit_position / 8;
        let bit_offset = bit_position % 8;

        // Assign a unique value to each status variant
        let status_value = match update.status {
            Status::VALID => 0b0000_0000,               // VALID = 0
            Status::INVALID => 0b0000_0001,             // INVALID = 1
            Status::SUSPENDED => 0b0000_0010,           // SUSPENDED = 2
            Status::APPLICATIONSPECIFIC => 0b0000_0011, // APPLICATIONSPECIFIC = 3
        };

        // Mask and set the status value in the appropriate position
        if bits == 8 {
            status_array[byte_index] = status_value;
        } else {
            let mask = ((1 << bits) - 1) << bit_offset;
            status_array[byte_index] &= !mask;
            status_array[byte_index] |= (status_value << bit_offset) & mask;

            // Handle cases where the status spans across two bytes
            if bit_offset + bits > 8 {
                let next_byte_index = byte_index + 1;
                let next_bit_offset = 8 - bit_offset;
                let next_mask = (1 << (bits - next_bit_offset)) - 1;
                if next_byte_index < status_array.len() {
                    status_array[next_byte_index] &= !next_mask;
                    status_array[next_byte_index] |= status_value >> next_bit_offset;
                }
            }
        }
    }

    // Compress the updated status array using zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&status_array)
        .map_err(|e| StatusListError::CompressionError(e.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|e| StatusListError::CompressionError(e.to_string()))?;

    // Base64url encode the compressed data without padding
    Ok(encode(&compressed))
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

    pub fn setup(bits: i8) -> (AppState, Arc<RwLock<HashMap<String, StatusListToken>>>) {
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
        let existing_status_list = StatusList { bits, lst };

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
        let appstate = setup(1);

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

    #[test]
    fn test_update_status_with_bits_set_to_8() {
        let original_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0011,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
        ];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_status_array).unwrap();
        let compressed = encoder.finish().unwrap();

        // Base64 encode the compressed data
        let lst = encode(&compressed);

        // Step 2: Define new status updates
        let status_updates = vec![
            StatusUpdate {
                index: 4,
                status: Status::INVALID,
            },
            StatusUpdate {
                index: 7,
                status: Status::SUSPENDED,
            },
        ];

        let updated_lst =
            update_status(lst, status_updates, 8).expect("Failed to update status list");

        let decoded = decode(&updated_lst).expect("Failed to decode base64");
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut updated_status_array = Vec::new();
        decoder
            .read_to_end(&mut updated_status_array)
            .expect("Failed to decompress");

        let expected_status_array = vec![
            0b0000_0000,
            0b0000_0001,
            0b0000_0010,
            0b0000_0011,
            0b0000_0001,
            0b0000_0000,
            0b0000_0000,
            0b0000_0010,
        ];
        assert_eq!(
            updated_status_array, expected_status_array,
            "The status array was not updated correctly"
        );
    }

    #[tokio::test]
    async fn test_update_with_bits_value_set_to_2() {
        let original_lst = vec![0b00011011, 0b00000000]; // Each byte holds 4 statuses (2 bits each)

        // Compress and encode the original status list
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_lst).unwrap();
        let compressed_lst = encoder.finish().unwrap();
        let lst = encode(&compressed_lst);

        let status_updates = vec![
            StatusUpdate {
                index: 1,
                status: Status::VALID,
            }, // Change index 1 from INVALID to VALID
            StatusUpdate {
                index: 8,
                status: Status::VALID,
            }, // Add index 8 as VALID
        ];

        let updated_lst =
            update_status(lst, status_updates, 2).expect("Failed to update status list");

        let decoded_lst = decode(&updated_lst).expect("Failed to decode base64");
        let mut decompressed_lst = Vec::new();
        ZlibDecoder::new(&decoded_lst[..])
            .read_to_end(&mut decompressed_lst)
            .unwrap();

        let expected_lst = vec![0b00010011, 0b00000000, 0b00000000]; // Adjusted statuses with added index 8

        assert_eq!(
            decompressed_lst, expected_lst,
            "The updated status list does not match the expected list."
        );
    }

    #[tokio::test]
    async fn test_malformed_body() {
        let appstate = setup(1);

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
        let appstate = setup(1);

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
        let appstate = setup(1);

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
        let appstate = setup(1);

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
