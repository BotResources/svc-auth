//! GET /auth/check -- auth subrequest endpoint.
//!
//! Called by nginx `auth_request` or k8s ingress middlewares on every proxied
//! request. Validates credentials (JWT cookie or bearer token).
//!
//! Two behaviors, toggled by `AppState.auth_check_silent_refresh`:
//!
//! **true (default)** -- legacy nginx/OpenResty mode. On expired JWT, rotate
//! tokens and return 200 + Set-Cookie. On invalid JWT, return 200 + clear
//! cookies. Always 200; the middleware forwards the new cookies to the client.
//!
//! **false** -- k8s ingress mode (Traefik ForwardAuth, nginx-ingress
//! `auth-url`, Envoy ExternalAuthz). On expired / invalid / corrupt JWT,
//! return 401. No token rotation, no Set-Cookie. The client catches 401 and
//! calls `/auth/refresh` explicitly (standard SPA pattern).
//!
//! Valid JWT, valid bearer, and no-credentials branches return 200 in both
//! modes. Unknown bearer tokens return 401; KV errors return 502.
//!
//! svc-auth does NOT build Passports or resolve identity. It validates
//! credentials and rejects unrecognized ones.

use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::cookie::{
    build_access_cookie, build_clear_access_cookie, build_clear_refresh_cookie,
    build_refresh_cookie, extract_access_cookie, extract_refresh_cookie,
};
use crate::jwt::JwtError;

pub async fn auth_check_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // 1. Check for JWT cookie (browser requests, including WS upgrade).
    if let Some(access_token) = extract_access_cookie(&headers, &state.cookie_config) {
        return handle_jwt_cookie(&state, &access_token, &headers).await;
    }

    // 2. Check for bearer token in Authorization header.
    if let Some(auth_value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        return handle_bearer(&state, auth_value).await;
    }

    // 3. No credentials -- anonymous.
    StatusCode::OK.into_response()
}

/// Handle JWT cookie validation. Behavior on expired / invalid JWT depends
/// on AppState.auth_check_silent_refresh.
async fn handle_jwt_cookie(state: &AppState, token: &str, headers: &HeaderMap) -> Response {
    match state.jwt.verify_access_token(token) {
        Ok(_claims) => {
            // Valid JWT -- let through. No Set-Cookie needed.
            StatusCode::OK.into_response()
        }
        Err(JwtError::Expired) => {
            if state.auth_check_silent_refresh {
                silent_refresh(state, headers).await
            } else {
                tracing::debug!("auth_check: expired JWT, silent refresh disabled, 401");
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        Err(_) => {
            if state.auth_check_silent_refresh {
                tracing::debug!("auth_check: invalid JWT cookie, clearing cookies");
                clear_cookies_response(state)
            } else {
                tracing::debug!("auth_check: invalid JWT cookie, silent refresh disabled, 401");
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

/// Attempt silent refresh using the refresh token cookie.
async fn silent_refresh(state: &AppState, headers: &HeaderMap) -> Response {
    let refresh_jwt = match extract_refresh_cookie(headers, &state.cookie_config) {
        Some(t) => t,
        None => {
            // No refresh cookie -- clear access cookie, anonymous.
            tracing::debug!("auth_check: expired JWT, no refresh cookie");
            return clear_access_cookie_response(state);
        }
    };

    // Verify refresh token JWT.
    let claims = match state.jwt.verify_refresh_token(&refresh_jwt) {
        Ok(c) => c,
        Err(JwtError::Expired) => {
            tracing::debug!("auth_check: refresh token expired");
            return clear_cookies_response(state);
        }
        Err(_) => {
            tracing::debug!("auth_check: invalid refresh token");
            return clear_cookies_response(state);
        }
    };

    // Parse jti to look up in database.
    let jti = match uuid::Uuid::parse_str(&claims.jti) {
        Ok(id) => id,
        Err(_) => return clear_cookies_response(state),
    };

    // Look up refresh token in NATS KV.
    let (token_row, revision) = match state.refresh_store.find_by_id(jti).await {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            tracing::debug!("auth_check: refresh token not found");
            return clear_cookies_response(state);
        }
        Err(e) => {
            tracing::error!(error = %e, "auth_check: error looking up refresh token");
            return clear_cookies_response(state);
        }
    };

    // Family revocation check (blocklist in NATS KV).
    if state
        .refresh_store
        .is_family_revoked(token_row.family_id)
        .await
    {
        tracing::debug!("auth_check: token family revoked");
        return clear_cookies_response(state);
    }

    // Reuse detection: if token was already used, revoke the entire family.
    if token_row.used_at.is_some() {
        tracing::warn!(
            family_id = %token_row.family_id,
            "auth_check: refresh token reuse detected, revoking family"
        );
        let _ = state.refresh_store.revoke_family(token_row.family_id).await;
        return clear_cookies_response(state);
    }

    // Rotate: sign new tokens.
    let email = &claims.sub;
    let new_access = match state.jwt.sign_access_token(email) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "auth_check: failed to sign new access token");
            return clear_cookies_response(state);
        }
    };

    let (new_refresh_jwt, new_token_id, new_hash) = match state.jwt.sign_refresh_token(email) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "auth_check: failed to sign new refresh token");
            return clear_cookies_response(state);
        }
    };

    // Store new refresh token.
    let new_token = crate::refresh_store::RefreshToken {
        id: new_token_id,
        email: email.clone(),
        token_hash: new_hash,
        family_id: token_row.family_id,
        used_at: None,
        replaced_by: None,
        created_at: chrono::Utc::now(),
    };

    if let Err(e) = state.refresh_store.store(&new_token).await {
        tracing::error!(error = %e, "auth_check: failed to store new refresh token");
        return clear_cookies_response(state);
    }

    // Now mark old token as used (new row exists, FK satisfied).
    if let Err(e) = state
        .refresh_store
        .mark_used(jti, new_token_id, revision)
        .await
    {
        tracing::error!(error = %e, "auth_check: failed to mark old refresh token as used");
        return clear_cookies_response(state);
    }

    tracing::debug!(email = %email, "auth_check: silent refresh successful");

    // Return 200 with new cookies.
    let access_cookie = build_access_cookie(&new_access, &state.cookie_config);
    let refresh_cookie = build_refresh_cookie(&new_refresh_jwt, &state.cookie_config);

    let mut response = StatusCode::OK.into_response();
    let hdrs = response.headers_mut();
    hdrs.insert(
        SET_COOKIE,
        access_cookie.parse().expect("cookie is valid ASCII"),
    );
    hdrs.append(
        SET_COOKIE,
        refresh_cookie.parse().expect("cookie is valid ASCII"),
    );
    response
}

/// Handle bearer token in Authorization header.
///
/// Valid token → 200, unknown token → 401, KV error → 502,
/// no validator configured → 200 (anonymous fallback).
async fn handle_bearer(state: &AppState, auth_value: &str) -> Response {
    let token = if auth_value.len() >= 7 && auth_value[..7].eq_ignore_ascii_case("bearer ") {
        &auth_value[7..]
    } else {
        auth_value
    };

    let Some(ref validator) = state.bearer_validator else {
        tracing::debug!("auth_check: no bearer validator configured, treating as anonymous");
        return StatusCode::OK.into_response();
    };

    match validator.is_valid(token).await {
        Ok(true) => {
            tracing::debug!("auth_check: bearer token valid");
            StatusCode::OK.into_response()
        }
        Ok(false) => {
            tracing::debug!("auth_check: bearer token not recognized");
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "auth_check: NATS KV bearer lookup failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Build a 200 response that clears both cookies.
fn clear_cookies_response(state: &AppState) -> Response {
    let clear_access = build_clear_access_cookie(&state.cookie_config);
    let clear_refresh = build_clear_refresh_cookie(&state.cookie_config);

    let mut response = StatusCode::OK.into_response();
    let hdrs = response.headers_mut();
    hdrs.insert(
        SET_COOKIE,
        clear_access.parse().expect("cookie is valid ASCII"),
    );
    hdrs.append(
        SET_COOKIE,
        clear_refresh.parse().expect("cookie is valid ASCII"),
    );
    response
}

/// Build a 200 response that clears only the access cookie.
fn clear_access_cookie_response(state: &AppState) -> Response {
    let clear_access = build_clear_access_cookie(&state.cookie_config);
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        clear_access.parse().expect("cookie is valid ASCII"),
    );
    response
}
