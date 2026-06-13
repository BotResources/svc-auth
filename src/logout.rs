use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::cookie::{
    build_clear_access_cookie, build_clear_refresh_cookie, extract_refresh_cookie,
};

pub async fn logout_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(ref token_jwt) = extract_refresh_cookie(&headers, &state.cookie_config)
        && let Ok(claims) = state.jwt.verify_refresh_token(token_jwt)
        && let Ok(jti) = uuid::Uuid::parse_str(&claims.jti)
        && let Ok(Some((row, _revision))) = state.refresh_store.find_by_id(jti).await
    {
        let _ = state.refresh_store.revoke_family(row.family_id).await;
    }

    let clear_access = build_clear_access_cookie(&state.cookie_config);
    let clear_refresh = build_clear_refresh_cookie(&state.cookie_config);

    let body = serde_json::json!({ "status": "logged_out" });
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
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
