use std::time::Duration;

use br_auth_contract::{BearerEntry, BearerSealKey, SealedBearer, bearer_token_kv_key, open};
use br_auth_identity_util::BearerPublisher;
use br_core_kernel::{Actor, UserId};
use br_test_harness::{FabricTestNats, SpawnedProcess};
use br_util_nats_fabric::KvKey;
use reqwest::Client;
use uuid::Uuid;

const SVC_AUTH_BIN: &str = env!("CARGO_BIN_EXE_svc-auth");
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const JWT_SECRET: &str = "e2e-test-secret-key-at-least-32-chars!";
const JWT_ISSUER: &str = "svc-auth";

const SEAL_KEY_BYTES: [u8; 32] = [7u8; 32];
const SEAL_KEY_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

const KNOWN_USER_ID: Uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
const KNOWN_TOKEN_ID: Uuid = Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000);
const RAW_TOKEN: &str = "brk_sealed_bearer_under_test";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn provisioned_nats() -> FabricTestNats {
    FabricTestNats::start()
        .await
        .with_published_language()
        .await
        .with_ephemeral_auth()
        .await
}

fn spawn_envs(port: u16, nats_url: &str) -> Vec<(String, String)> {
    vec![
        ("PORT".into(), port.to_string()),
        ("NATS_URL".into(), nats_url.to_string()),
        ("JWT_SECRET".into(), JWT_SECRET.into()),
        ("JWT_ISSUER".into(), JWT_ISSUER.into()),
        ("ENVIRONMENT".into(), "local".into()),
        ("SECURE_COOKIES".into(), "false".into()),
        ("AUTH_CHECK_SILENT_REFRESH".into(), "false".into()),
        ("BEARER_SEAL_KEY".into(), SEAL_KEY_B64.into()),
    ]
}

fn seal_key(bytes: &[u8]) -> BearerSealKey {
    BearerSealKey::from_bytes(bytes).expect("32-byte seal key")
}

fn known_entry() -> BearerEntry {
    BearerEntry {
        actor: Actor::Human(UserId::from(KNOWN_USER_ID)),
        token_id: KNOWN_TOKEN_ID,
    }
}

#[tokio::test]
async fn bearer_sealed_in_published_language_resolves() {
    let nats = provisioned_nats().await;

    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let envs = spawn_envs(port, &nats.url());
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut svc = SpawnedProcess::spawn(SVC_AUTH_BIN, &[], &env_refs);
    svc.wait_for_http_ok(&format!("{base_url}/livez"), BOOT_TIMEOUT)
        .await
        .expect("svc-auth did not become live");

    let key = seal_key(&SEAL_KEY_BYTES);
    let entry = known_entry();
    let publisher = BearerPublisher::open(nats.fabric(), seal_key(&SEAL_KEY_BYTES))
        .await
        .expect("open BearerPublisher on PUBLISHED_LANGUAGE");
    publisher
        .put_bearer(RAW_TOKEN, &entry)
        .await
        .expect("publish the sealed bearer");

    let contract_key = KvKey::new(bearer_token_kv_key(RAW_TOKEN)).expect("contract KvKey");

    let stored = nats
        .pl_get_raw(&contract_key)
        .await
        .expect("a value must exist at the contract key in PUBLISHED_LANGUAGE");
    assert!(
        contract_key.as_str().starts_with("identity/bearer_tokens/"),
        "contract key must live under identity/bearer_tokens/, got {}",
        contract_key.as_str()
    );

    let at_rest = String::from_utf8_lossy(&stored);
    assert!(
        !at_rest.contains(&KNOWN_USER_ID.to_string()),
        "stored bytes leak the user_id (not sealed): {at_rest}"
    );
    assert!(
        !at_rest.contains(&KNOWN_TOKEN_ID.to_string()),
        "stored bytes leak the token_id (not sealed): {at_rest}"
    );
    assert!(
        !at_rest.contains(RAW_TOKEN),
        "stored bytes leak the raw token (not sealed): {at_rest}"
    );

    let sealed: SealedBearer =
        serde_json::from_slice(&stored).expect("stored value is a SealedBearer envelope");
    let opened = open(&key, RAW_TOKEN, &sealed).expect("open with the correct key recovers it");
    assert_eq!(
        opened, entry,
        "recovered entry must equal the published one"
    );
    let wrong_key = seal_key(&[9u8; 32]);
    assert!(
        open(&wrong_key, RAW_TOKEN, &sealed).is_err(),
        "open with a different key must fail (real AEAD, not base64)"
    );

    let client = Client::new();
    let resp = client
        .get(format!("{base_url}/auth/check"))
        .header("authorization", format!("Bearer {RAW_TOKEN}"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let resolved_user = resp
        .headers()
        .get("x-auth-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resolved_token = resp
        .headers()
        .get("x-auth-token-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let expected_user = KNOWN_USER_ID.to_string();
    let expected_token = KNOWN_TOKEN_ID.to_string();
    assert_eq!(
        status, 200,
        "the sealed bearer in PUBLISHED_LANGUAGE must authenticate at /auth/check (got {status})"
    );
    assert_eq!(
        resolved_user.as_deref(),
        Some(expected_user.as_str()),
        "/auth/check must expose the resolved actor in X-Auth-User-Id (got {resolved_user:?})"
    );
    assert_eq!(
        resolved_token.as_deref(),
        Some(expected_token.as_str()),
        "/auth/check must expose the resolved token id in X-Auth-Token-Id (got {resolved_token:?})"
    );

    svc.shutdown().await;
    nats.shutdown().await;
}

#[tokio::test]
async fn unresolved_bearer_is_rejected() {
    let nats = provisioned_nats().await;

    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let envs = spawn_envs(port, &nats.url());
    let env_refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut svc = SpawnedProcess::spawn(SVC_AUTH_BIN, &[], &env_refs);
    svc.wait_for_http_ok(&format!("{base_url}/livez"), BOOT_TIMEOUT)
        .await
        .expect("svc-auth did not become live");

    let client = Client::new();
    let resp = client
        .get(format!("{base_url}/auth/check"))
        .header("authorization", "Bearer brk_unknown_unsealed_token")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "a presented bearer that does not resolve in PUBLISHED_LANGUAGE must be rejected with 401 (fail-closed)"
    );

    svc.shutdown().await;
    nats.shutdown().await;
}
