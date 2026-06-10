//! E2E tests for svc-auth.
//!
//! These tests hit the real service — no mocks, no bypass. The OIDC path is
//! exercised against the pilotable test IdPs from br-e2e-harness (see
//! docker-compose.e2e.yml): real discovery, real JWKS, real RS256 signatures.
//! Requires: NATS + the two IdP fixtures + svc-auth (see scripts/e2e/up.sh).
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

// =============================================================================
// OIDC verification path (ws-cc-platform#6) — against the pilotable test IdPs.
//
// Provider A (:9100, claim `email`) carries the happy path and the kid-miss
// rotation. Provider B (:9101, Entra-shaped claim `preferred_username`) proves
// multi-provider routing and isolates the cooldown counter assertions: tests
// run in parallel, so every test that does NOT want to depend on a JWKS
// refresh mints with `e2e-key-0`, published at startup and therefore always
// in svc-auth's cache. The e2e stack runs JWKS_REFRESH_COOLDOWN_SECONDS=2.
// =============================================================================

fn idp_a_url() -> String {
    std::env::var("OIDC_IDP_A_URL").unwrap_or_else(|_| "http://localhost:9100".to_string())
}

fn idp_b_url() -> String {
    std::env::var("OIDC_IDP_B_URL").unwrap_or_else(|_| "http://localhost:9101".to_string())
}

async fn idp_mint(idp_url: &str, body: serde_json::Value) -> String {
    let resp = Client::new()
        .post(format!("{idp_url}/admin/mint"))
        .json(&body)
        .send()
        .await
        .expect("IdP fixture unreachable — is docker-compose.e2e.yml up?");
    assert_eq!(resp.status(), 200, "IdP /admin/mint failed");
    let minted: serde_json::Value = resp.json().await.unwrap();
    minted["id_token"].as_str().unwrap().to_string()
}

/// Default rotate gesture: publish the next pool key and make it active.
/// Returns the new active kid.
async fn idp_rotate(idp_url: &str) -> String {
    let resp = Client::new()
        .post(format!("{idp_url}/admin/rotate"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "IdP /admin/rotate failed");
    let state: serde_json::Value = resp.json().await.unwrap();
    state["active_kid"].as_str().unwrap().to_string()
}

async fn idp_jwks_fetches(idp_url: &str) -> u64 {
    let state: serde_json::Value = Client::new()
        .get(format!("{idp_url}/admin/state"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    state["jwks_fetches"].as_u64().unwrap()
}

async fn post_auth_token(client: &Client, id_token: &str) -> reqwest::Response {
    client
        .post(format!("{}/auth/token", base_url()))
        .json(&serde_json::json!({"grant_type": "id_token", "id_token": id_token}))
        .send()
        .await
        .unwrap()
}

/// Value of the first non-clearing `Set-Cookie` named `name`.
fn cookie_value(resp: &reqwest::Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|c| c.starts_with(&prefix))
        .map(|c| {
            c[prefix.len()..]
                .split(';')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .find(|v| !v.is_empty())
}

#[tokio::test]
#[ignore]
async fn oidc_valid_id_token_yields_cookie_session_end_to_end() {
    let client = Client::new();
    let id_token = idp_mint(
        &idp_a_url(),
        serde_json::json!({"email": "carol@example.com", "kid": "e2e-key-0"}),
    )
    .await;

    let resp = post_auth_token(&client, &id_token).await;
    assert_eq!(
        resp.status(),
        200,
        "a verified id_token must open a session"
    );
    let access = cookie_value(&resp, "access_token").expect("access_token cookie must be set");
    let refresh = cookie_value(&resp, "refresh_token").expect("refresh_token cookie must be set");

    // The issued access cookie authenticates /auth/check.
    let check = client
        .get(format!("{}/auth/check", base_url()))
        .header("cookie", format!("access_token={access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        check.status(),
        200,
        "OIDC-issued access token must pass /auth/check"
    );

    // The issued refresh cookie rotates.
    let rotated = client
        .post(format!("{}/auth/refresh", base_url()))
        .header("cookie", format!("refresh_token={refresh}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        rotated.status(),
        200,
        "OIDC-issued refresh token must rotate"
    );
    let new_refresh = cookie_value(&rotated, "refresh_token").expect("rotated refresh cookie");
    assert_ne!(
        new_refresh, refresh,
        "refresh token must rotate, not repeat"
    );
}

#[tokio::test]
#[ignore]
async fn oidc_kid_miss_triggers_jwks_refresh_end_to_end() {
    let client = Client::new();
    let idp_a = idp_a_url();

    let before = idp_jwks_fetches(&idp_a).await;
    // The IdP rotates: a new key enters the JWKS and signs from now on.
    // svc-auth's cache predates it, so verification requires a re-fetch.
    let new_kid = idp_rotate(&idp_a).await;
    let id_token = idp_mint(
        &idp_a,
        serde_json::json!({"email": "dave@example.com", "kid": new_kid}),
    )
    .await;

    let resp = post_auth_token(&client, &id_token).await;
    assert_eq!(
        resp.status(),
        200,
        "a token signed with a freshly rotated key must verify after a JWKS refresh"
    );
    let after = idp_jwks_fetches(&idp_a).await;
    assert!(
        after > before,
        "svc-auth must have re-fetched the JWKS on kid miss ({before} -> {after})"
    );
}

#[tokio::test]
#[ignore]
async fn oidc_unknown_key_rejected_and_jwks_refetch_cooldown_gated() {
    let client = Client::new();
    let idp_b = idp_b_url();
    let cooldown = std::time::Duration::from_millis(2500);

    fn unknown_key_token(kid: &str) -> serde_json::Value {
        serde_json::json!({
            "email": "eve@example.com",
            "email_claim": "preferred_username",
            "aud": "e2e-client-b",
            "kid": kid,
        })
    }

    // Clear any recent refresh window (svc-auth startup also counts as one).
    tokio::time::sleep(cooldown).await;
    let before = idp_jwks_fetches(&idp_b).await;

    // 1. Unknown kid: svc-auth re-fetches the JWKS, still unknown → rejected.
    let t1 = idp_mint(&idp_b, unknown_key_token("e2e-key-5")).await;
    assert_eq!(post_auth_token(&client, &t1).await.status(), 401);
    let after_first = idp_jwks_fetches(&idp_b).await;
    assert_eq!(
        after_first,
        before + 1,
        "the first unknown kid must trigger exactly one JWKS re-fetch"
    );

    // 2. Another unknown kid inside the cooldown: rejected WITHOUT re-fetching.
    let t2 = idp_mint(&idp_b, unknown_key_token("e2e-key-4")).await;
    assert_eq!(post_auth_token(&client, &t2).await.status(), 401);
    assert_eq!(
        idp_jwks_fetches(&idp_b).await,
        after_first,
        "within the cooldown the JWKS must not be re-fetched"
    );

    // 3. Once the cooldown expires the re-fetch happens again — and the token
    //    is still rejected (the key is genuinely not in the JWKS).
    tokio::time::sleep(cooldown).await;
    let t3 = idp_mint(&idp_b, unknown_key_token("e2e-key-5")).await;
    assert_eq!(post_auth_token(&client, &t3).await.status(), 401);
    assert_eq!(
        idp_jwks_fetches(&idp_b).await,
        after_first + 1,
        "after the cooldown a re-fetch is allowed again"
    );
}

#[tokio::test]
#[ignore]
async fn oidc_multi_provider_routing_by_issuer() {
    let client = Client::new();

    // Provider B, with its Entra-shaped email claim, verifies end-to-end.
    let b_token = idp_mint(
        &idp_b_url(),
        serde_json::json!({
            "email": "frank@example.com",
            "email_claim": "preferred_username",
            "kid": "e2e-key-0",
        }),
    )
    .await;
    let ok = post_auth_token(&client, &b_token).await;
    assert_eq!(
        ok.status(),
        200,
        "provider B's id_token must be routed by iss and verified"
    );

    // A correctly-signed token whose iss matches no configured provider.
    let alien = idp_mint(
        &idp_a_url(),
        serde_json::json!({
            "email": "frank@example.com",
            "kid": "e2e-key-0",
            "claims": {"iss": "http://unknown-issuer.test"},
        }),
    )
    .await;
    let ko = post_auth_token(&client, &alien).await;
    assert_eq!(ko.status(), 401, "an unknown issuer must be rejected");
}

#[tokio::test]
#[ignore]
async fn oidc_wrong_audience_rejected() {
    let client = Client::new();
    let id_token = idp_mint(
        &idp_a_url(),
        serde_json::json!({"email": "gina@example.com", "kid": "e2e-key-0", "aud": "not-our-client"}),
    )
    .await;
    let resp = post_auth_token(&client, &id_token).await;
    assert_eq!(
        resp.status(),
        401,
        "an id_token with a wrong audience must be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn oidc_expired_id_token_rejected() {
    let client = Client::new();
    // -120s clears jsonwebtoken's default 60s leeway.
    let id_token = idp_mint(
        &idp_a_url(),
        serde_json::json!({"email": "hugo@example.com", "kid": "e2e-key-0", "expires_in_secs": -120}),
    )
    .await;
    let resp = post_auth_token(&client, &id_token).await;
    assert_eq!(resp.status(), 401, "an expired id_token must be rejected");
}
