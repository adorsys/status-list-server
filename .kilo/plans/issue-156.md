# Plan: Improve API Error Handling (Issue #156)

## Objective

Improve the API error handling to match the structured, machine-readable style used by the cloud-identity-wallet project. Ensure consistent error responses across all endpoints.

## Current State Analysis

The codebase has **inconsistent error response formats**:

| Error Type | Response Format | Location |
|------------|-----------------|----------|
| `StatusListError` | Plain text body | `src/web/handlers/status_list/error.rs:65` |
| `AuthenticationError` | JSON `{"error": "msg"}` | `src/web/auth/errors.rs:29` |
| `CredentialError` | Mixed inline handling | `src/web/handlers/issue_credential.rs:32-56` |

**Problems identified:**
1. No unified `ApiError` struct
2. Mix of plain text and JSON responses
3. No error code fields for programmatic handling
4. No correlation IDs for log tracing
5. Handlers convert errors manually (no centralized mapping)

## Deliverables

### 1. Define Unified `ApiError` Response Struct

**File:** `src/web/errors.rs` (new)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,           // Machine-readable error code
    pub message: String,         // Human-readable description
    pub trace_id: String,        // Correlation ID for log tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,   // Optional additional context
}

impl ApiError {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            details: None,
        }
    }
    
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}
```

### 2. Create Central Error Mapping Layer

**File:** `src/web/errors.rs` (new)

Implement `From` conversions from all error types:
- `StatusListError` → `ApiError`
- `AuthenticationError` → `ApiError`
- `RepositoryError` → `ApiError`
- `CredentialError` → `ApiError`

### 3. Implement Unified `IntoResponse` 

**File:** `src/web/errors.rs` (new)

```rust
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.determine_status_code();
        tracing::error!(
            trace_id = %self.trace_id,
            error = %self.error,
            "API error: {}",
            self.message
        );
        (status, Json(self)).into_response()
    }
}
```

### 4. Replace All Ad-Hoc Error Responses

#### Update `src/web/handlers/status_list/error.rs`
- Remove inline `IntoResponse` impl
- Add `From<StatusListError> for ApiError` impl
- Keep error enum unchanged

#### Update `src/web/auth/errors.rs`  
- Remove inline `IntoResponse` impl
- Add `From<AuthenticationError> for ApiError` impl

#### Update `src/web/handlers/issue_credential.rs`
- Remove inline error matching
- Delegate to `ApiError::from(err).into_response()`

### 5. Add Logging/Tracing (Structured Logs)

Each `ApiError` generates:
- A `trace_id` (UUID) for correlation
- Structured `tracing::error!` with error code, message, and trace_id

### 6. Add Tests

**New file:** `tests/error_response_tests.rs`

```rust
#[tokio::test]
async fn test_status_list_error_serializes_correctly() {
    let error = ApiError::from(StatusListError::StatusListNotFound);
    assert_eq!(error.error, "STATUS_LIST_NOT_FOUND");
    // ...
}
```

### 7. Error Code Mapping

| Error Type | Error Code |
|------------|------------|
| `StatusListError::InvalidListId` | `INVALID_LIST_ID` |
| `StatusListError::StatusListNotFound` | `STATUS_LIST_NOT_FOUND` |
| `StatusListError::StatusListAlreadyExists` | `STATUS_LIST_ALREADY_EXISTS` |
| `AuthenticationError::InvalidAuthorizationHeader` | `INVALID_AUTH_HEADER` |
| `AuthenticationError::JwtError` | `JWT_ERROR` |
| `RepositoryError::DuplicateEntry` | `DUPLICATE_ENTRY` |

## Files to Modify

1. **`src/web/errors.rs`** (create) - New unified ApiError module
2. **`src/web/handlers/status_list/error.rs`** - Remove IntoResponse, add From impl
3. **`src/web/auth/errors.rs`** - Remove IntoResponse, add From impl
4. **`src/web/handlers/issue_credential.rs`** - Simplify to use ApiError
5. **`src/web/mod.rs`** - Export new errors module
6. **`tests/error_response_tests.rs`** (create) - Error response tests

## Files NOT to Modify

- Database error module (`src/database/error.rs`) - Keep internal
- Utility error modules (`src/utils/errors.rs`, `src/utils/keygen.rs`) - Keep internal
- Cert manager error modules - Keep internal

## Acceptance Criteria

- [ ] All error responses use unified JSON format `{"error": "...", "message": "...", "trace_id": "..."}`
- [ ] `trace_id` present in all error responses
- [ ] Structured logging attached to all error responses
- [ ] Error response tests pass
- [ ] `cargo fmt`, `cargo clippy`, `cargo build`, `cargo test` all pass
- [ ] OpenAPI spec documents the standard error schema (handled in #147)

## CI Commands

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo build
cargo nextest run
cargo machete
```