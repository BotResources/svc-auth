//! GET /health -- standard health check endpoint.
//!
//! Returns 200 if NATS KV buckets are reachable, 503 otherwise.

use axum::extract::State;
use axum::http::StatusCode;

use crate::AppState;

pub async fn health_handler(
    State(state): State<AppState>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let refresh_store_ok = state.refresh_store.is_healthy().await;

    let bearer_ok = match state.bearer_validator {
        Some(ref validator) => validator.is_healthy().await,
        None => true, // No NATS bearer bucket configured — not a failure
    };

    if refresh_store_ok && bearer_ok {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "ok" })),
        )
    } else {
        let mut details = serde_json::Map::new();
        if !refresh_store_ok {
            details.insert("refresh_store".into(), "unreachable".into());
        }
        if !bearer_ok {
            details.insert("bearer_validator".into(), "unreachable".into());
        }
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "degraded",
                "details": details,
            })),
        )
    }
}
