//! E2E tests for svc-auth.
//!
//! These tests hit the real service (no mocks, no ALLOW_INSECURE).
//! Requires: NATS + svc-auth running (see scripts/e2e/up.sh).
//!
//! Run: cargo test --test e2e -- --ignored

use reqwest::Client;

fn base_url() -> String {
    std::env::var("SVC_AUTH_URL").unwrap_or_else(|_| "http://localhost:8002".to_string())
}

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "e2e-test-secret-key-at-least-32-chars!".to_string())
}

fn mint_access_token(email: &str, expired: bool) -> String {
    use jsonwebtoken::{EncodingKey, Header};
    let now = chrono::Utc::now().timestamp();
    let (iat, exp) = if expired {
        (now - 300, now - 60)
    } else {
        (now, now + 900)
    };
    let claims = serde_json::json!({
        "sub": email,
        "iss": "svc-auth",
        "iat": iat,
        "exp": exp,
    });
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .unwrap()
}

fn mint_refresh_token(email: &str, expired: bool) -> String {
    use jsonwebtoken::{EncodingKey, Header};
    let now = chrono::Utc::now().timestamp();
    let (iat, exp) = if expired {
        (now - 700_000, now - 60)
    } else {
        (now, now + 604_800)
    };
    let jti = uuid::Uuid::now_v7().to_string();
    let claims = serde_json::json!({
        "sub": email,
        "iss": "svc-auth",
        "iat": iat,
        "exp": exp,
        "jti": jti,
    });
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .unwrap()
}

// =============================================================================
// Health
// =============================================================================

#[tokio::test]
#[ignore]
async fn health_returns_200_when_nats_is_reachable() {
    let client = Client::new();
    let resp = client
        .get(format!("{}/health", base_url()))
        .send()
        .await
        .expect("failed to reach svc-auth");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

// =============================================================================
// Issue #16: session ID cookie for anonymous and authenticated users
// =============================================================================

#[tokio::test]
#[ignore]
async fn auth_check_anonymous_sets_session_id_cookie() {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        set_cookies.iter().any(|c| c.contains("session_id=")),
        "anonymous /auth/check should set session_id cookie, got: {set_cookies:?}"
    );

    let session_cookie = set_cookies
        .iter()
        .find(|c| c.contains("session_id="))
        .unwrap();
    assert!(
        session_cookie.contains("HttpOnly"),
        "session_id cookie must be HttpOnly"
    );
    assert!(
        session_cookie.contains("SameSite=Lax"),
        "session_id cookie must use SameSite=Lax"
    );
    assert!(
        !session_cookie.contains("Max-Age"),
        "session_id cookie must NOT have Max-Age (session-scoped)"
    );
}

#[tokio::test]
#[ignore]
async fn auth_check_preserves_existing_session_id() {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("cookie", "session_id=existing-session-uuid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        !set_cookies.iter().any(|c| c.contains("session_id=")),
        "should NOT set session_id when one already exists, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn auth_check_bearer_does_not_set_session_id() {
    let client = Client::new();
    let valid_token = mint_access_token("alice@example.com", false);

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("authorization", format!("Bearer {valid_token}"))
        .send()
        .await
        .unwrap();

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        !set_cookies.iter().any(|c| c.contains("session_id=")),
        "bearer token requests should NOT get session_id cookie, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn auth_check_with_jwt_sets_session_id_when_missing() {
    let client = Client::new();
    let valid_token = mint_access_token("alice@example.com", false);

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("cookie", format!("access_token={valid_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        set_cookies.iter().any(|c| c.contains("session_id=")),
        "JWT request without session_id should get one, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn logout_does_not_clear_session_id() {
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/logout", base_url()))
        .header("cookie", "session_id=keep-me")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        !set_cookies.iter().any(|c| c.contains("session_id=")),
        "logout should NOT touch session_id cookie, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn refresh_no_session_sets_session_id() {
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/refresh", base_url()))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        set_cookies.iter().any(|c| c.contains("session_id=")),
        "/auth/refresh without session_id should set one, got: {set_cookies:?}"
    );
}

// =============================================================================
// Issue #13: expired JWT must return 401 from /auth/check
// =============================================================================

#[tokio::test]
#[ignore]
async fn auth_check_expired_jwt_cookie_returns_401() {
    let client = Client::new();
    let expired_token = mint_access_token("alice@example.com", true);

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("cookie", format!("access_token={expired_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expired JWT cookie should return 401 (AUTH_CHECK_SILENT_REFRESH=false)"
    );
}

#[tokio::test]
#[ignore]
async fn auth_check_expired_jwt_as_bearer_returns_401() {
    let client = Client::new();
    let expired_token = mint_access_token("alice@example.com", true);

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("authorization", format!("Bearer {expired_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expired JWT sent as Bearer token should return 401, not 200"
    );
}

#[tokio::test]
#[ignore]
async fn auth_check_valid_jwt_cookie_returns_200() {
    let client = Client::new();
    let valid_token = mint_access_token("alice@example.com", false);

    let resp = client
        .get(format!("{}/auth/check", base_url()))
        .header("cookie", format!("access_token={valid_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "valid JWT cookie should return 200");
}

// =============================================================================
// Issue #5: /auth/refresh 401 must include cookie-clearing Set-Cookie headers
// =============================================================================

#[tokio::test]
#[ignore]
async fn refresh_expired_token_returns_401_with_clear_cookies() {
    let client = Client::new();
    let expired_refresh = mint_refresh_token("alice@example.com", true);

    let resp = client
        .post(format!("{}/auth/refresh", base_url()))
        .header("cookie", format!("refresh_token={expired_refresh}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expired refresh token should return 401"
    );

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        set_cookies
            .iter()
            .any(|c| c.contains("access_token=;") || c.contains("access_token=;")),
        "401 from /auth/refresh should clear access_token cookie, got: {set_cookies:?}"
    );
    assert!(
        set_cookies
            .iter()
            .any(|c| c.contains("refresh_token=;") || c.contains("refresh_token=;")),
        "401 from /auth/refresh should clear refresh_token cookie, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn refresh_unknown_token_returns_401_with_clear_cookies() {
    let client = Client::new();
    // Valid signature but JTI not in NATS KV → "invalid_refresh_token"
    let unknown_refresh = mint_refresh_token("bob@example.com", false);

    let resp = client
        .post(format!("{}/auth/refresh", base_url()))
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "refresh_token": unknown_refresh }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "unknown refresh token (not in KV) should return 401"
    );

    let set_cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        set_cookies.iter().any(|c| c.contains("access_token=")),
        "401 from /auth/refresh should clear access_token cookie, got: {set_cookies:?}"
    );
    assert!(
        set_cookies.iter().any(|c| c.contains("refresh_token=")),
        "401 from /auth/refresh should clear refresh_token cookie, got: {set_cookies:?}"
    );
}

#[tokio::test]
#[ignore]
async fn refresh_missing_token_returns_200_no_session() {
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/refresh", base_url()))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "missing refresh token should return 200 with no_session"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "no_session");
}
