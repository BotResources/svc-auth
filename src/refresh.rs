//! POST /auth/refresh -- refresh token rotation.
//!
//! Reads the refresh token from an HttpOnly cookie (browser clients) or
//! from the request body (non-browser clients). Validates the token, rotates
//! it (marks old as used, creates new in same family), and sets new cookies.
//!
//! svc-auth does not look up users or check statuses. The refresh token
//! carries the email in its sub claim. A new JWT is signed with the same email.

use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::cookie::{
    build_access_cookie, build_clear_access_cookie, build_clear_refresh_cookie,
    build_refresh_cookie, build_session_cookie, extract_refresh_cookie, extract_session_cookie,
};
use crate::error::AppError;
use crate::jwt::JwtError;
use crate::refresh_store::RefreshToken;

#[derive(Debug, Deserialize, Default)]
pub struct RefreshRequest {
    pub refresh_token: Option<String>,
}

pub async fn refresh_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<axum::Json<RefreshRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = body.map(|j| j.0).unwrap_or_default();
    let existing_session = extract_session_cookie(&headers, &state.cookie_config);

    let mut response = match handle_refresh(&state, &body, &headers).await {
        Ok(r) => r,
        Err(e) => {
            let mut response = e.into_response();
            if response.status() == StatusCode::UNAUTHORIZED {
                let clear_access = build_clear_access_cookie(&state.cookie_config);
                let clear_refresh = build_clear_refresh_cookie(&state.cookie_config);
                let hdrs = response.headers_mut();
                hdrs.insert(
                    SET_COOKIE,
                    clear_access.parse().expect("cookie is valid ASCII"),
                );
                hdrs.append(
                    SET_COOKIE,
                    clear_refresh.parse().expect("cookie is valid ASCII"),
                );
            }
            response
        }
    };

    if existing_session.is_none() {
        let sid = uuid::Uuid::now_v7().to_string();
        let cookie = build_session_cookie(&sid, &state.cookie_config);
        response.headers_mut().append(
            SET_COOKIE,
            cookie.parse().expect("cookie is valid ASCII"),
        );
    }

    response
}

async fn handle_refresh(
    state: &AppState,
    body: &RefreshRequest,
    headers: &HeaderMap,
) -> Result<Response, AppError> {
    // Resolve refresh token from body (priority) or cookie.
    let refresh_jwt = match resolve_refresh_token(body, headers, &state.cookie_config) {
        Some(t) => t,
        None => {
            // No token available -- return 200 with status.
            let resp = serde_json::json!({ "status": "no_session" });
            return Ok((StatusCode::OK, axum::Json(resp)).into_response());
        }
    };

    // Verify refresh token JWT.
    let claims = state
        .jwt
        .verify_refresh_token(&refresh_jwt)
        .map_err(|e| match e {
            JwtError::Expired => AppError::Unauthorized("refresh_token_expired".into()),
            JwtError::Invalid(_) => AppError::Unauthorized("invalid_refresh_token".into()),
        })?;

    // Parse jti.
    let jti = Uuid::parse_str(&claims.jti)
        .map_err(|_| AppError::Unauthorized("invalid_refresh_token".into()))?;

    // Look up refresh token in NATS KV.
    let (token_row, revision) = state
        .refresh_store
        .find_by_id(jti)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Unauthorized("invalid_refresh_token".into()))?;

    // Family revocation check.
    if state
        .refresh_store
        .is_family_revoked(token_row.family_id)
        .await
    {
        return Err(AppError::Unauthorized("token_family_revoked".into()));
    }

    // Reuse detection.
    if token_row.used_at.is_some() {
        tracing::warn!(
            family_id = %token_row.family_id,
            "refresh: token reuse detected, revoking family"
        );
        let _ = state.refresh_store.revoke_family(token_row.family_id).await;
        return Err(AppError::Unauthorized("token_reuse_detected".into()));
    }

    // Rotate: sign new tokens with the same email.
    let email = &claims.sub;
    let new_access = state
        .jwt
        .sign_access_token(email)
        .map_err(AppError::Internal)?;

    let (new_refresh_jwt, new_token_id, new_hash) = state
        .jwt
        .sign_refresh_token(email)
        .map_err(AppError::Internal)?;

    // Store new refresh token.
    let new_token = RefreshToken {
        id: new_token_id,
        email: email.clone(),
        token_hash: new_hash,
        family_id: token_row.family_id,
        used_at: None,
        replaced_by: None,
        created_at: chrono::Utc::now(),
    };

    state
        .refresh_store
        .store(&new_token)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Now mark old token as used (new row exists, FK satisfied).
    state
        .refresh_store
        .mark_used(jti, new_token_id, revision)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let access_ttl = state.jwt.access_ttl_secs();

    // Build cookies.
    let access_cookie = build_access_cookie(&new_access, &state.cookie_config);
    let refresh_cookie = build_refresh_cookie(&new_refresh_jwt, &state.cookie_config);

    let resp_body = serde_json::json!({
        "token_type": "Bearer",
        "expires_in": access_ttl,
    });

    let mut response = (StatusCode::OK, axum::Json(resp_body)).into_response();
    let hdrs = response.headers_mut();
    hdrs.insert(
        SET_COOKIE,
        access_cookie.parse().expect("cookie is valid ASCII"),
    );
    hdrs.append(
        SET_COOKIE,
        refresh_cookie.parse().expect("cookie is valid ASCII"),
    );
    Ok(response)
}

/// Resolve refresh token: body takes precedence over cookie.
fn resolve_refresh_token(
    body: &RefreshRequest,
    headers: &HeaderMap,
    config: &crate::cookie::CookieConfig,
) -> Option<String> {
    if let Some(ref t) = body.refresh_token
        && !t.is_empty()
    {
        return Some(t.clone());
    }
    extract_refresh_cookie(headers, config)
}
