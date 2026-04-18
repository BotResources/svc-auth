//! POST /auth/token -- OIDC id_token exchange.
//!
//! Accepts an id_token from the frontend's PKCE flow, validates it against
//! the matching OIDC provider, and returns an internal JWT as HttpOnly cookies.
//! The JWT sub claim is the verified email address.
//!
//! svc-auth signs a JWT for ANY verified email. It does not check whether
//! the user exists, is disabled, or has permissions.

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::cookie::{build_access_cookie, build_refresh_cookie};
use crate::error::AppError;
use crate::oidc_validator::parse_insecure_claims;
use crate::refresh_store::RefreshToken;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub id_token: Option<String>,
}

pub async fn token_handler(
    State(state): State<AppState>,
    body: Result<axum::Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match body {
        Ok(axum::Json(b)) => b,
        Err(_) => return AppError::Validation("invalid request body".into()).into_response(),
    };

    match handle_token(&state, &body).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn handle_token(state: &AppState, body: &TokenRequest) -> Result<Response, AppError> {
    // Validate grant_type.
    let grant_type = body
        .grant_type
        .as_deref()
        .ok_or_else(|| AppError::Validation("grant_type is required".into()))?;

    if grant_type != "id_token" {
        return Err(AppError::Validation(
            "unsupported grant_type; expected \"id_token\"".into(),
        ));
    }

    // Validate id_token presence.
    let id_token = body
        .id_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Validation("id_token is required".into()))?;

    // Verify the OIDC id_token and extract email.
    let claims = if state.allow_insecure {
        // In local dev, try OIDC verification first; fall back to insecure parsing.
        if state.oidc.has_providers() {
            match state.oidc.verify_id_token(id_token).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "OIDC verification failed, using ALLOW_INSECURE fallback"
                    );
                    parse_insecure_claims(id_token).map_err(AppError::Unauthorized)?
                }
            }
        } else {
            parse_insecure_claims(id_token).map_err(AppError::Unauthorized)?
        }
    } else {
        state.oidc.verify_id_token(id_token).await.map_err(|msg| {
            tracing::warn!(error = %msg, "OIDC id_token verification failed");
            AppError::Unauthorized(msg)
        })?
    };

    let email = &claims.email;
    if email.is_empty() {
        return Err(AppError::Validation("no_email_in_token".into()));
    }

    // Sign internal JWT with sub: email.
    let access_token = state
        .jwt
        .sign_access_token(email)
        .map_err(AppError::Internal)?;

    // Create refresh token.
    let (refresh_jwt, token_id, token_hash) = state
        .jwt
        .sign_refresh_token(email)
        .map_err(AppError::Internal)?;

    let family_id = Uuid::now_v7();
    let refresh_token = RefreshToken {
        id: token_id,
        email: email.clone(),
        token_hash,
        family_id,
        used_at: None,
        replaced_by: None,
        created_at: chrono::Utc::now(),
    };

    state
        .refresh_store
        .store(&refresh_token)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to store refresh token");
            AppError::Internal("failed to create session".to_string())
        })?;

    let access_ttl = state.jwt.access_ttl_secs();

    // Build cookies.
    let access_cookie = build_access_cookie(&access_token, &state.cookie_config);
    let refresh_cookie = build_refresh_cookie(&refresh_jwt, &state.cookie_config);

    // Response body -- access token is NOT included, only metadata.
    let resp_body = serde_json::json!({
        "token_type": "Bearer",
        "expires_in": access_ttl,
    });

    let mut response = (StatusCode::OK, axum::Json(resp_body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        SET_COOKIE,
        access_cookie.parse().expect("cookie is valid ASCII"),
    );
    headers.append(
        SET_COOKIE,
        refresh_cookie.parse().expect("cookie is valid ASCII"),
    );
    Ok(response)
}
