use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::cookie::{
    build_access_cookie, build_refresh_cookie, build_session_cookie, extract_session_cookie,
};
use crate::error::AppError;
use crate::refresh_store::RefreshToken;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub id_token: Option<String>,
}

pub async fn token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<axum::Json<TokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let body = match body {
        Ok(axum::Json(b)) => b,
        Err(_) => return AppError::Validation("invalid request body".into()).into_response(),
    };

    let existing_session = extract_session_cookie(&headers, &state.cookie_config);

    match handle_token(&state, &body).await {
        Ok(mut r) => {
            if existing_session.is_none() {
                let sid = Uuid::now_v7().to_string();
                let cookie = build_session_cookie(&sid, &state.cookie_config);
                r.headers_mut()
                    .append(SET_COOKIE, cookie.parse().expect("cookie is valid ASCII"));
            }
            r
        }
        Err(e) => e.into_response(),
    }
}

async fn handle_token(state: &AppState, body: &TokenRequest) -> Result<Response, AppError> {
    let grant_type = body
        .grant_type
        .as_deref()
        .ok_or_else(|| AppError::Validation("grant_type is required".into()))?;

    if grant_type != "id_token" {
        return Err(AppError::Validation(
            "unsupported grant_type; expected \"id_token\"".into(),
        ));
    }

    let id_token = body
        .id_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Validation("id_token is required".into()))?;

    let claims = state.oidc.verify_id_token(id_token).await.map_err(|msg| {
        tracing::warn!(error = %msg, "OIDC id_token verification failed");
        AppError::Unauthorized(msg)
    })?;

    let email = &claims.email;
    if email.is_empty() {
        return Err(AppError::Validation("no_email_in_token".into()));
    }

    let access_token = state
        .jwt
        .sign_access_token(email)
        .map_err(AppError::Internal)?;

    let (refresh_jwt, token_id) = state
        .jwt
        .sign_refresh_token(email)
        .map_err(AppError::Internal)?;

    let family_id = Uuid::now_v7();
    let refresh_token = RefreshToken {
        id: token_id,
        email: email.clone(),
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

    let access_cookie = build_access_cookie(&access_token, &state.cookie_config);
    let refresh_cookie = build_refresh_cookie(&refresh_jwt, &state.cookie_config);

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
