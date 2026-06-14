use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use br_core_auth::session_cookie_name;
use br_test_harness::oidc::state::{MintRequest, RotateRequest};
use br_test_harness::oidc::{IdpConfig, IdpState, router};
use br_test_harness::{SpawnedNats, SpawnedProcess, recreate_kv};
use reqwest::Client;
use serde_json::Value;

const SVC_AUTH_BIN: &str = env!("CARGO_BIN_EXE_svc-auth");
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const JWT_SECRET: &str = "e2e-test-secret-key-at-least-32-chars!";
const JWT_ISSUER: &str = "svc-auth";

const PROVIDER_A_CLIENT: &str = "e2e-client";
const PROVIDER_B_CLIENT: &str = "e2e-client-b";

const REQUIRED_BUCKETS: &[&str] = &[
    "bearer_tokens",
    "auth_refresh_tokens",
    "auth_revoked_families",
];

struct Idp {
    issuer: String,
    state: Arc<IdpState>,
}

impl Idp {
    // Bind a 127.0.0.1:0 listener FIRST so the issuer can be the IdP's real
    // serving URL — svc-auth resolves jwks_uri from the discovery document
    // ({issuer}/jwks) and fetches it, so the issuer must be reachable.
    async fn start(client_id: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind IdP listener");
        let addr = listener.local_addr().expect("IdP local_addr");
        let issuer = format!("http://{addr}");

        let state = Arc::new(IdpState::new(IdpConfig {
            issuer: issuer.clone(),
            key_pool_size: 3,
            initial_published: 1,
            default_client_id: client_id.to_string(),
        }));

        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        Self { issuer, state }
    }

    fn mint(&self, req: &MintRequest) -> String {
        self.state.mint(req).expect("IdP mint").id_token
    }

    fn rotate(&self) -> String {
        let snap = self
            .state
            .rotate(&RotateRequest::default())
            .expect("IdP rotate");
        snap["active_kid"].as_str().unwrap().to_string()
    }

    fn jwks_fetches(&self) -> u64 {
        self.state.snapshot()["jwks_fetches"].as_u64().unwrap()
    }
}

struct TestContext {
    base_url: String,
    nats: Option<SpawnedNats>,
    svc: Option<SpawnedProcess>,
    idp_a: Idp,
    idp_b: Idp,
}

impl TestContext {
    // Bring up two in-process OIDC IdPs, real SpawnedNats with the three KV
    // buckets DECLARED (svc-auth binds, never creates — a missing bucket keeps
    // readiness DOWN or fails the boot), then spawn the real svc-auth binary
    // wired to all of them. `buckets` selects which buckets exist before boot.
    async fn start(buckets: &[&str]) -> Self {
        let idp_a = Idp::start(PROVIDER_A_CLIENT).await;
        let idp_b = Idp::start(PROVIDER_B_CLIENT).await;

        let nats = SpawnedNats::start().await;
        declare_buckets(&nats.url(), buckets).await;

        let port = free_port();
        let base_url = format!("http://127.0.0.1:{port}");

        let envs = spawn_envs(port, &nats.url(), &idp_a, &idp_b);
        let env_refs: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let mut svc = SpawnedProcess::spawn(SVC_AUTH_BIN, &[], &env_refs);

        svc.wait_for_http_ok(&format!("{base_url}/livez"), BOOT_TIMEOUT)
            .await
            .expect("svc-auth did not become live");

        Self {
            base_url,
            nats: Some(nats),
            svc: Some(svc),
            idp_a,
            idp_b,
        }
    }

    async fn full() -> Self {
        Self::start(REQUIRED_BUCKETS).await
    }

    async fn ready(&self) -> bool {
        let client = Client::new();
        match client.get(format!("{}/readyz", self.base_url)).send().await {
            Ok(resp) => resp.status() == 200,
            Err(_) => false,
        }
    }

    async fn shutdown(mut self) {
        if let Some(svc) = self.svc.take() {
            svc.shutdown().await;
        }
        if let Some(nats) = self.nats.take() {
            nats.shutdown().await;
        }
    }
}

// svc-auth binds 0.0.0.0:PORT; a per-test free port keeps concurrently-running
// scenarios from colliding (passed explicitly via the spawn env).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_envs(port: u16, nats_url: &str, idp_a: &Idp, idp_b: &Idp) -> Vec<(String, String)> {
    vec![
        ("PORT".into(), port.to_string()),
        ("NATS_URL".into(), nats_url.to_string()),
        ("JWT_SECRET".into(), JWT_SECRET.into()),
        ("JWT_ISSUER".into(), JWT_ISSUER.into()),
        ("ENVIRONMENT".into(), "test".into()),
        ("SECURE_COOKIES".into(), "false".into()),
        ("AUTH_CHECK_SILENT_REFRESH".into(), "false".into()),
        ("JWKS_REFRESH_COOLDOWN_SECONDS".into(), "1".into()),
        ("OIDC_E2EA_DISCOVERY_URL".into(), idp_a.issuer.clone()),
        ("OIDC_E2EA_CLIENT_ID".into(), PROVIDER_A_CLIENT.into()),
        ("OIDC_E2EB_DISCOVERY_URL".into(), idp_b.issuer.clone()),
        ("OIDC_E2EB_CLIENT_ID".into(), PROVIDER_B_CLIENT.into()),
        ("OIDC_E2EB_EMAIL_CLAIM".into(), "preferred_username".into()),
    ]
}

async fn declare_buckets(nats_url: &str, buckets: &[&str]) {
    let client = br_test_harness::nats::connect(nats_url)
        .await
        .expect("connect to SpawnedNats");
    let js = jetstream::new(client);
    for bucket in buckets {
        recreate_kv(&js, bucket).await;
    }
}

fn redirectless() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn set_cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect()
}

fn cookie_value(resp: &reqwest::Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    set_cookies(resp)
        .into_iter()
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

// The internal HS256 JWT minting stays bespoke — there is no harness equivalent
// for svc-auth's own access/refresh tokens (the harness OIDC fixture mints
// RS256 id_tokens, a different credential).
fn mint_internal_jwt(email: &str, refresh: bool, expired: bool) -> String {
    use jsonwebtoken::{EncodingKey, Header};
    let now = chrono::Utc::now().timestamp();
    let (iat, exp) = match (refresh, expired) {
        (false, false) => (now, now + 900),
        (false, true) => (now - 300, now - 60),
        (true, false) => (now, now + 604_800),
        (true, true) => (now - 700_000, now - 60),
    };
    let mut claims = serde_json::json!({
        "sub": email,
        "iss": JWT_ISSUER,
        "iat": iat,
        "exp": exp,
    });
    if refresh {
        claims["jti"] = serde_json::json!(uuid::Uuid::now_v7().to_string());
    }
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn post_auth_token(client: &Client, base: &str, id_token: &str) -> reqwest::Response {
    client
        .post(format!("{base}/auth/token"))
        .json(&serde_json::json!({"grant_type": "id_token", "id_token": id_token}))
        .send()
        .await
        .unwrap()
}

fn mint_req(email: &str) -> MintRequest {
    MintRequest {
        email: email.to_string(),
        aud: None,
        email_claim: None,
        kid: None,
        expires_in_secs: None,
        claims: None,
        omit_kid_header: false,
    }
}

// ---------------------------------------------------------------------------
// Probes & readiness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn livez_returns_200() {
    // Given a fully-provisioned svc-auth
    let ctx = TestContext::full().await;
    let client = Client::new();

    // When /livez is probed
    let resp = client
        .get(format!("{}/livez", ctx.base_url))
        .send()
        .await
        .unwrap();

    // Then it is alive
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "alive");

    ctx.shutdown().await;
}

#[tokio::test]
async fn readyz_returns_200_when_all_buckets_present() {
    // Given svc-auth booted with all three KV buckets declared
    let ctx = TestContext::full().await;
    let client = Client::new();

    // When /readyz is probed
    let resp = client
        .get(format!("{}/readyz", ctx.base_url))
        .send()
        .await
        .unwrap();

    // Then it is ready
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ready");

    ctx.shutdown().await;
}

#[tokio::test]
async fn metrics_exposes_prometheus_exposition() {
    let ctx = TestContext::full().await;
    let client = Client::new();

    let resp = client
        .get(format!("{}/metrics", ctx.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("process_"));

    ctx.shutdown().await;
}

// ---------------------------------------------------------------------------
// Fail-loud: bearer_tokens bucket absent at boot → svc-auth exits non-zero
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bearer_bucket_absent_fails_boot() {
    // Given the bearer_tokens bucket is NOT declared (only the refresh buckets),
    // bearer_tokens is a required declared bucket — like the refresh buckets, its
    // absence is fail-loud, not a degraded-but-running mode.
    let idp_a = Idp::start(PROVIDER_A_CLIENT).await;
    let idp_b = Idp::start(PROVIDER_B_CLIENT).await;
    let nats = SpawnedNats::start().await;
    declare_buckets(
        &nats.url(),
        &["auth_refresh_tokens", "auth_revoked_families"],
    )
    .await;

    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let envs = spawn_envs(port, &nats.url(), &idp_a, &idp_b);
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut svc = SpawnedProcess::spawn(SVC_AUTH_BIN, &[], &env_refs);

    // When it boots, it never comes live — it exits because a declared bucket is missing
    let outcome = svc
        .await_boot(&format!("{base_url}/livez"), BOOT_TIMEOUT)
        .await;

    // Then the process exited non-zero (K8s reschedules), it did not stay up
    let status = outcome.exit_status().unwrap_or_else(|| {
        panic!("svc-auth must EXIT when bearer_tokens is absent, got {outcome:?}")
    });
    assert!(
        !status.success(),
        "svc-auth must exit non-zero when bearer_tokens is absent, got {status}"
    );

    svc.shutdown().await;
    nats.shutdown().await;
}

// ---------------------------------------------------------------------------
// Unknown bearer against a HEALTHY bucket resolves anonymous, never 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_bearer_against_healthy_bucket_resolves_anonymous_200() {
    // Given a fully-provisioned svc-auth (bearer_tokens present and healthy)
    let ctx = TestContext::full().await;
    assert!(ctx.ready().await, "precondition: svc-auth must be ready");
    let client = Client::new();

    // When /auth/check is called with a bearer credential that is NOT in the bucket
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("authorization", "Bearer unknown-bearer-not-in-kv")
        .send()
        .await
        .unwrap();

    // Then it resolves to anonymous (200), never 401 — an unresolvable credential
    // against a healthy bucket is "no session", not "rejected".
    assert_eq!(
        resp.status(),
        200,
        "unknown bearer against a healthy bucket must resolve anonymous 200, never 401"
    );

    ctx.shutdown().await;
}

// ---------------------------------------------------------------------------
// /auth/check session-cookie behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_check_anonymous_sets_session_cookie() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = redirectless();

    // When an anonymous client calls /auth/check
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cookies = set_cookies(&resp);

    // Then a session cookie is set, HttpOnly, SameSite=Lax, session-scoped
    let session = cookies
        .iter()
        .find(|c| c.starts_with(&format!("{session_name}=")))
        .unwrap_or_else(|| {
            panic!("anonymous /auth/check must set {session_name}, got: {cookies:?}")
        });
    assert!(
        session.contains("HttpOnly"),
        "session cookie must be HttpOnly"
    );
    assert!(
        session.contains("SameSite=Lax"),
        "session cookie must be SameSite=Lax"
    );
    assert!(
        !session.contains("Max-Age"),
        "session cookie must be session-scoped (no Max-Age)"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_preserves_existing_session_cookie() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = redirectless();

    // When a client already carrying a session cookie calls /auth/check
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("cookie", format!("{session_name}=existing-session-uuid"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Then no new session cookie is minted
    let cookies = set_cookies(&resp);
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with(&format!("{session_name}="))),
        "must NOT re-set the session cookie when one exists, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_bearer_does_not_set_session_cookie() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = Client::new();

    // When a bearer-credential request hits /auth/check
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("authorization", "Bearer unknown-bearer-not-in-kv")
        .send()
        .await
        .unwrap();

    // Then no session cookie is issued on the bearer path
    let cookies = set_cookies(&resp);
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with(&format!("{session_name}="))),
        "bearer requests must NOT get a session cookie, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_valid_jwt_cookie_sets_session_when_missing() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = Client::new();
    let token = mint_internal_jwt("alice@example.com", false, false);

    // When a valid JWT cookie arrives without a session cookie
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("cookie", format!("access_token={token}"))
        .send()
        .await
        .unwrap();

    // Then 200, and a session cookie is minted
    assert_eq!(resp.status(), 200, "valid JWT cookie must pass /auth/check");
    let cookies = set_cookies(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("{session_name}="))),
        "valid JWT without a session cookie must get one, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_expired_jwt_cookie_returns_401() {
    // Given AUTH_CHECK_SILENT_REFRESH=false
    let ctx = TestContext::full().await;
    let client = Client::new();
    let token = mint_internal_jwt("alice@example.com", false, true);

    // When an expired JWT cookie hits /auth/check
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("cookie", format!("access_token={token}"))
        .send()
        .await
        .unwrap();

    // Then 401 (no silent refresh)
    assert_eq!(
        resp.status(),
        401,
        "expired JWT cookie must 401 when silent refresh is off"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_unknown_jwt_as_bearer_resolves_anonymous_200() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    let token = mint_internal_jwt("alice@example.com", false, true);

    // When an internal JWT is presented on the Bearer path it is an unknown opaque
    // token to the bearer validator (not a PAT in bearer_tokens).
    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    // Then it resolves anonymous (200), never 401.
    assert_eq!(
        resp.status(),
        200,
        "an unknown bearer against a healthy bucket must resolve anonymous 200, never 401"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn auth_check_valid_jwt_cookie_returns_200() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    let token = mint_internal_jwt("alice@example.com", false, false);

    let resp = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("cookie", format!("access_token={token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "valid JWT cookie must return 200");

    ctx.shutdown().await;
}

// ---------------------------------------------------------------------------
// /auth/logout and /auth/refresh session behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_does_not_clear_session_cookie() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/logout", ctx.base_url))
        .header("cookie", format!("{session_name}=keep-me"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let cookies = set_cookies(&resp);
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with(&format!("{session_name}="))),
        "logout must NOT touch the session cookie, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn refresh_no_session_sets_session_cookie() {
    let ctx = TestContext::full().await;
    let session_name = session_cookie_name(false);
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/refresh", ctx.base_url))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let cookies = set_cookies(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("{session_name}="))),
        "/auth/refresh without a session cookie must set one, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn refresh_missing_token_returns_200_no_session() {
    let ctx = TestContext::full().await;
    let client = Client::new();

    let resp = client
        .post(format!("{}/auth/refresh", ctx.base_url))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "missing refresh token must be 200 no_session"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "no_session");

    ctx.shutdown().await;
}

#[tokio::test]
async fn refresh_expired_token_returns_401_clearing_cookies() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    let expired = mint_internal_jwt("alice@example.com", true, true);

    let resp = client
        .post(format!("{}/auth/refresh", ctx.base_url))
        .header("cookie", format!("refresh_token={expired}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired refresh token must 401");

    let cookies = set_cookies(&resp);
    assert!(
        cookies.iter().any(|c| c.contains("access_token=;")),
        "401 from /auth/refresh must clear access_token, got: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.contains("refresh_token=;")),
        "401 from /auth/refresh must clear refresh_token, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn refresh_unknown_token_returns_401_clearing_cookies() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    // A well-signed but never-stored refresh token (jti not in KV).
    let unknown = mint_internal_jwt("bob@example.com", true, false);

    let resp = client
        .post(format!("{}/auth/refresh", ctx.base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "refresh_token": unknown }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "unknown refresh token (not in KV) must 401"
    );

    let cookies = set_cookies(&resp);
    assert!(
        cookies.iter().any(|c| c.starts_with("access_token=")),
        "401 from /auth/refresh must clear access_token, got: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("refresh_token=")),
        "401 from /auth/refresh must clear refresh_token, got: {cookies:?}"
    );

    ctx.shutdown().await;
}

// ---------------------------------------------------------------------------
// OIDC id_token exchange (via the in-process IdP fixture)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_valid_id_token_opens_a_rotating_cookie_session() {
    // Given a verified id_token from provider A
    let ctx = TestContext::full().await;
    let client = Client::new();
    let id_token = ctx.idp_a.mint(&mint_req("carol@example.com"));

    // When it is exchanged at /auth/token
    let resp = post_auth_token(&client, &ctx.base_url, &id_token).await;
    assert_eq!(
        resp.status(),
        200,
        "a verified id_token must open a session"
    );
    let access = cookie_value(&resp, "access_token").expect("access_token cookie");
    let refresh = cookie_value(&resp, "refresh_token").expect("refresh_token cookie");

    // Then the issued access token passes /auth/check
    let check = client
        .get(format!("{}/auth/check", ctx.base_url))
        .header("cookie", format!("access_token={access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        check.status(),
        200,
        "OIDC-issued access token must pass /auth/check"
    );

    // And the refresh token rotates (new value, not a repeat)
    let rotated = client
        .post(format!("{}/auth/refresh", ctx.base_url))
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

    ctx.shutdown().await;
}

#[tokio::test]
async fn oidc_kid_miss_triggers_a_jwks_refresh() {
    // Given a token signed with a freshly rotated (initially-unknown) key
    let ctx = TestContext::full().await;
    let client = Client::new();

    // svc-auth stamps last_refresh at boot (discovery); wait out the 1s cooldown
    // so the kid-miss is actually allowed to re-fetch rather than being suppressed.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let before = ctx.idp_a.jwks_fetches();
    let new_kid = ctx.idp_a.rotate();
    let id_token = ctx.idp_a.mint(&MintRequest {
        kid: Some(new_kid),
        ..mint_req("dave@example.com")
    });

    // When it is exchanged, svc-auth misses the kid and re-fetches the JWKS
    let resp = post_auth_token(&client, &ctx.base_url, &id_token).await;
    assert_eq!(
        resp.status(),
        200,
        "a token from a rotated key must verify after JWKS refresh"
    );

    // Then a JWKS re-fetch is observable on the IdP
    let after = ctx.idp_a.jwks_fetches();
    assert!(
        after > before,
        "svc-auth must re-fetch the JWKS on kid miss ({before} -> {after})"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn oidc_unknown_key_rejected_with_refetch_cooldown() {
    // Given provider B and a cooldown of 1s (env JWKS_REFRESH_COOLDOWN_SECONDS)
    let ctx = TestContext::full().await;
    let client = Client::new();
    let cooldown = Duration::from_millis(2500);

    fn unknown_key_token(ctx: &TestContext, kid: &str) -> String {
        ctx.idp_b.mint(&MintRequest {
            aud: Some(PROVIDER_B_CLIENT.to_string()),
            email_claim: Some("preferred_username".to_string()),
            kid: Some(kid.to_string()),
            ..mint_req("eve@example.com")
        })
    }

    tokio::time::sleep(cooldown).await;
    let before = ctx.idp_b.jwks_fetches();

    // When an unknown signing key is presented the first time, exactly one re-fetch fires.
    // e2e-key-1 / e2e-key-2 exist in the pool but are never published, so they sign a
    // token whose kid svc-auth has never cached — the kid-miss the test is about.
    let t1 = unknown_key_token(&ctx, "e2e-key-1");
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &t1).await.status(),
        401
    );
    let after_first = ctx.idp_b.jwks_fetches();
    assert_eq!(
        after_first,
        before + 1,
        "first unknown kid must trigger exactly one re-fetch"
    );

    // Within the cooldown a second unknown kid does NOT re-fetch
    let t2 = unknown_key_token(&ctx, "e2e-key-2");
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &t2).await.status(),
        401
    );
    assert_eq!(
        ctx.idp_b.jwks_fetches(),
        after_first,
        "within the cooldown the JWKS must not be re-fetched"
    );

    // After the cooldown a re-fetch is allowed again
    tokio::time::sleep(cooldown).await;
    let t3 = unknown_key_token(&ctx, "e2e-key-1");
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &t3).await.status(),
        401
    );
    assert_eq!(
        ctx.idp_b.jwks_fetches(),
        after_first + 1,
        "after the cooldown a re-fetch is allowed again"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn oidc_multi_provider_routing_by_issuer() {
    let ctx = TestContext::full().await;
    let client = Client::new();

    // Provider B is routed by its iss and verified
    let b_token = ctx.idp_b.mint(&MintRequest {
        aud: Some(PROVIDER_B_CLIENT.to_string()),
        email_claim: Some("preferred_username".to_string()),
        ..mint_req("frank@example.com")
    });
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &b_token)
            .await
            .status(),
        200,
        "provider B's id_token must be routed by iss and verified"
    );

    // A token bearing an unconfigured issuer is rejected
    let mut alien_claims = serde_json::Map::new();
    alien_claims.insert(
        "iss".into(),
        serde_json::json!("http://unknown-issuer.test"),
    );
    let alien = ctx.idp_a.mint(&MintRequest {
        claims: Some(alien_claims),
        ..mint_req("frank@example.com")
    });
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &alien)
            .await
            .status(),
        401,
        "an unknown issuer must be rejected"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn oidc_wrong_audience_rejected() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    let id_token = ctx.idp_a.mint(&MintRequest {
        aud: Some("not-our-client".to_string()),
        ..mint_req("gina@example.com")
    });
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &id_token)
            .await
            .status(),
        401,
        "an id_token with a wrong audience must be rejected"
    );

    ctx.shutdown().await;
}

#[tokio::test]
async fn oidc_expired_id_token_rejected() {
    let ctx = TestContext::full().await;
    let client = Client::new();
    let id_token = ctx.idp_a.mint(&MintRequest {
        expires_in_secs: Some(-120),
        ..mint_req("hugo@example.com")
    });
    assert_eq!(
        post_auth_token(&client, &ctx.base_url, &id_token)
            .await
            .status(),
        401,
        "an expired id_token must be rejected"
    );

    ctx.shutdown().await;
}
