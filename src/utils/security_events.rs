//! Security event logging for audit compliance
//!
//! All security events are logged with target="security" for separate routing.
//! This enables security/audit events to be captured separately from application logs,
//! making compliance auditing and incident investigation easier.
//!
//! # Example: Querying security events with jq
//!
//! ```bash
//! # View all security events
//! cargo run 2>&1 | jq 'select(.target == "security")'
//!
//! # View authentication failures
//! cargo run 2>&1 | jq 'select(.fields.event_type == "auth_failure")'
//! ```

/// Log an authentication failure event
///
/// # Arguments
/// * `issuer` - The issuer that attempted authentication
/// * `reason` - Human-readable reason for the failure
/// * `request_id` - The correlation ID for the request (if available)
#[track_caller]
pub(crate) fn log_auth_failure(issuer: &str, reason: &str, request_id: Option<&str>) {
    tracing::error!(
        target: "security",
        event_type = "auth_failure",
        issuer = %issuer,
        reason = %reason,
        request_id = request_id.unwrap_or("unknown"),
        "Authentication failed"
    );
}

/// Log an authorization/permission denied event
///
/// # Arguments
/// * `issuer` - The authenticated issuer attempting the action
/// * `resource` - The resource being accessed
/// * `action` - The action being attempted (e.g., "update_status", "publish")
/// * `request_id` - The correlation ID for the request (if available)
#[track_caller]
#[allow(dead_code)]
pub(crate) fn log_permission_denied(
    issuer: &str,
    resource: &str,
    action: &str,
    request_id: Option<&str>,
) {
    tracing::error!(
        target: "security",
        event_type = "permission_denied",
        issuer = %issuer,
        resource = %resource,
        action = %action,
        request_id = request_id.unwrap_or("unknown"),
        "Permission denied"
    );
}

/// Log suspicious activity that may indicate an attack
///
/// # Arguments
/// * `activity_type` - Category of suspicious activity (e.g., "rate_limit_exceeded", "invalid_token")
/// * `details` - Additional details about the activity
/// * `source_ip` - Client IP address (if available)
/// * `request_id` - The correlation ID for the request (if available)
#[track_caller]
pub(crate) fn log_suspicious_activity(
    activity_type: &str,
    details: &str,
    source_ip: Option<&str>,
    request_id: Option<&str>,
) {
    tracing::warn!(
        target: "security",
        event_type = "suspicious_activity",
        activity_type = %activity_type,
        details = %details,
        source_ip = source_ip.unwrap_or("unknown"),
        request_id = request_id.unwrap_or("unknown"),
        "Suspicious activity detected"
    );
}

/// Log a security event for token validation failures
///
/// # Arguments
/// * `error_type` - The type of token validation failure
/// * `issuer` - The issuer from the token (if extractable)
/// * `details` - Additional error details
/// * `request_id` - The correlation ID for the request (if available)
#[track_caller]
pub(crate) fn log_token_validation_failure(
    error_type: &str,
    issuer: Option<&str>,
    details: &str,
    request_id: Option<&str>,
) {
    tracing::error!(
        target: "security",
        event_type = "token_validation_failure",
        error_type = %error_type,
        issuer = issuer.unwrap_or("unknown"),
        details = %details,
        request_id = request_id.unwrap_or("unknown"),
        "Token validation failed"
    );
}

/// Log successful security-sensitive operations
///
/// # Arguments
/// * `operation` - The operation performed (e.g., "credential_issued", "status_updated")
/// * `issuer` - The issuer performing the operation
/// * `resource` - The affected resource
/// * `request_id` - The correlation ID for the request (if available)
#[track_caller]
pub(crate) fn log_security_event(
    operation: &str,
    issuer: &str,
    resource: &str,
    request_id: Option<&str>,
) {
    tracing::info!(
        target: "security",
        event_type = "security_event",
        operation = %operation,
        issuer = %issuer,
        resource = %resource,
        request_id = request_id.unwrap_or("unknown"),
        "Security event"
    );
}
