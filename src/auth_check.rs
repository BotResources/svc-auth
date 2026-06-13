use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::cookie::{
    build_access_cookie, build_clear_access_cookie, build_clear_refresh_cookie,
    build_refresh_cookie, build_session_cookie, extract_access_cookie, extract_refresh_cookie,
    extract_session_cookie,
};
use crate::jwt::JwtError;

pub async fn auth_check_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let existing_session = extract_session_cookie(&headers, &state.cookie_config);

    if let Some(access_token) = extract_access_cookie(&headers, &state.cookie_config) {
        let mut response = handle_jwt_cookie(&state, &access_token, &headers).await;
        append_session_cookie_if_needed(&mut response, existing_session.as_deref(), &state);
        return response;
    }

    if let Some(auth_value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        return handle_bearer(&state, auth_value).await;
    }

    let mut response = StatusCode::OK.into_response();
    append_session_cookie_if_needed(&mut response, existing_session.as_deref(), &state);
    response
}

async fn handle_jwt_cookie(state: &AppState, token: &str, headers: &HeaderMap) -> Response {
    match state.jwt.verify_access_token(token) {
        Ok(_claims) => StatusCode::OK.into_response(),
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

async fn silent_refresh(state: &AppState, headers: &HeaderMap) -> Response {
    let refresh_jwt = match extract_refresh_cookie(headers, &state.cookie_config) {
        Some(t) => t,
        None => {
            tracing::debug!("auth_check: expired JWT, no refresh cookie");
            return clear_access_cookie_response(state);
        }
    };

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

    let jti = match uuid::Uuid::parse_str(&claims.jti) {
        Ok(id) => id,
        Err(_) => return clear_cookies_response(state),
    };

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

    if state
        .refresh_store
        .is_family_revoked(token_row.family_id)
        .await
    {
        tracing::debug!("auth_check: token family revoked");
        return clear_cookies_response(state);
    }

    if token_row.used_at.is_some() {
        tracing::warn!(
            family_id = %token_row.family_id,
            "auth_check: refresh token reuse detected, revoking family"
        );
        let _ = state.refresh_store.revoke_family(token_row.family_id).await;
        return clear_cookies_response(state);
    }

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

    if let Err(e) = state
        .refresh_store
        .mark_used(jti, new_token_id, revision)
        .await
    {
        tracing::error!(error = %e, "auth_check: failed to mark old refresh token as used");
        return clear_cookies_response(state);
    }

    tracing::debug!(email = %email, "auth_check: silent refresh successful");

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

fn clear_access_cookie_response(state: &AppState) -> Response {
    let clear_access = build_clear_access_cookie(&state.cookie_config);
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        clear_access.parse().expect("cookie is valid ASCII"),
    );
    response
}

fn append_session_cookie_if_needed(
    response: &mut Response,
    existing: Option<&str>,
    state: &AppState,
) {
    if existing.is_some() {
        return;
    }
    let session_id = uuid::Uuid::now_v7().to_string();
    let cookie = build_session_cookie(&session_id, &state.cookie_config);
    response
        .headers_mut()
        .append(SET_COOKIE, cookie.parse().expect("cookie is valid ASCII"));
}
