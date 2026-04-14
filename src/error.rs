//! Two-layer error types for svc-auth REST endpoints.
//!
//! Application errors (Validation, Unauthorized, Internal) are converted
//! to HTTP JSON responses. Internal error messages are never leaked to the
//! client.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, "validation_error", msg.clone()),
            Self::Internal(msg) => {
                tracing::error!(error = %msg, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "an internal error occurred".to_string(),
                )
            }
        };

        let body = serde_json::json!({
            "error": error_code,
            "message": message,
        });

        (status, axum::Json(body)).into_response()
    }
}
