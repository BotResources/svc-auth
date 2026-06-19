use br_auth_contract::{BEARER_TOKENS_KEY_PREFIX, SealedBearer, bearer_token_kv_key, open};
use br_test_harness::FabricTestNats;
use br_util_nats_fabric::{FabricError, KvKey, KvPrefix};

use crate::anchor::Anchor;
use crate::error::{ConformanceError, Result};
use crate::fixture::{
    OTHER_TOKEN, SEAL_KEY_BYTES, TOKEN, encode_entry, human_entry, seal_key, service_entry,
};
use crate::outcome::{CheckId, CheckOutcome};

const DIRECTORY_USERS_PREFIX: &str = "identity/users/";

fn kv_key(value: &str) -> Result<KvKey> {
    KvKey::new(value).map_err(|e| ConformanceError::Kv(e.to_string()))
}

fn kv_prefix(value: &str) -> Result<KvPrefix> {
    KvPrefix::new(value).map_err(|e| ConformanceError::Kv(e.to_string()))
}

fn fabric_err(e: FabricError) -> ConformanceError {
    ConformanceError::Fabric(e.to_string())
}

pub async fn rides_published_language_consumer() -> Result<CheckOutcome> {
    let id = CheckId::RidesPublishedLanguageConsumer;
    let expected = "a Go-sealed bearer published to identity/bearer_tokens/<hash> via the real fabric \
                    PublishedLanguagePublisher is read back by the real PublishedLanguageReader scoped to \
                    the bearer prefix and opened through the lib into the original entry";
    let anchor = Anchor::build().await?;
    let nats = FabricTestNats::start()
        .await
        .with_published_language()
        .await;
    let outcome = rides_inner(id, expected, &anchor, &nats).await;
    nats.shutdown().await;
    outcome
}

async fn rides_inner(
    id: CheckId,
    expected: &str,
    anchor: &Anchor,
    nats: &FabricTestNats,
) -> Result<CheckOutcome> {
    let key = seal_key()?;

    for entry in [human_entry(), service_entry()] {
        let token = match &entry.actor {
            br_core_kernel::Actor::Service(_) => OTHER_TOKEN,
            _ => TOKEN,
        };
        let plaintext = encode_entry(&entry)?;
        let sealed = anchor.seal(&SEAL_KEY_BYTES, token, &plaintext).await?;

        let bearer_key = kv_key(&bearer_token_kv_key(token))?;
        nats.pl_publisher::<SealedBearer>()
            .await
            .put(&bearer_key, &sealed)
            .await
            .map_err(fabric_err)?;

        let collected = nats
            .pl_reader::<SealedBearer>()
            .await
            .entries(&kv_prefix(BEARER_TOKENS_KEY_PREFIX)?)
            .await
            .map_err(fabric_err)?;

        let Some(read_back) = collected.get(&bearer_key) else {
            return Ok(CheckOutcome::fail(
                id,
                expected,
                format!("{} key(s) under the bearer prefix", collected.len()),
                format!(
                    "the real published-language reader did not see the {} bearer key it just published",
                    actor_label(&entry.actor)
                ),
            ));
        };
        if read_back != &sealed {
            return Ok(CheckOutcome::fail(
                id,
                expected,
                "envelope changed in transit",
                format!(
                    "the {} SealedBearer did not round-trip the real fabric PL transport byte-identically",
                    actor_label(&entry.actor)
                ),
            ));
        }

        match open(&key, token, read_back) {
            Ok(opened) if opened == entry => {}
            Ok(opened) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("opened {opened:?}"),
                    "the PL-transported bearer opened into a different entry",
                ));
            }
            Err(e) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("open errored: {e}"),
                    "the lib could not open the PL-transported sealed bearer",
                ));
            }
        }
    }

    Ok(CheckOutcome::pass(
        id,
        expected,
        "the human + service bearers round-tripped the real fabric PL reader and opened through the lib",
    ))
}

fn actor_label(actor: &br_core_kernel::Actor) -> &'static str {
    match actor {
        br_core_kernel::Actor::Human(_) => "human",
        br_core_kernel::Actor::Service(_) => "service",
    }
}

pub async fn undecodable_bearer_value_fails_closed() -> Result<CheckOutcome> {
    let id = CheckId::UndecodableBearerValueFailsClosed;
    let expected = "a non-SealedBearer value published under the bearer prefix makes the bearer-scoped \
                    PublishedLanguageReader::<SealedBearer>().entries(prefix) fail closed with a \
                    FabricError::Decode naming the offending key (the scan does NOT silently skip it)";
    let nats = FabricTestNats::start()
        .await
        .with_published_language()
        .await;
    let outcome = undecodable_inner(id, expected, &nats).await;
    nats.shutdown().await;
    outcome
}

async fn undecodable_inner(
    id: CheckId,
    expected: &str,
    nats: &FabricTestNats,
) -> Result<CheckOutcome> {
    let garbage_key = kv_key(&format!(
        "{BEARER_TOKENS_KEY_PREFIX}{}",
        uuid::Uuid::now_v7().simple()
    ))?;
    let garbage_value = serde_json::json!({ "not_a_sealed_bearer": true });
    nats.pl_publisher::<serde_json::Value>()
        .await
        .put(&garbage_key, &garbage_value)
        .await
        .map_err(fabric_err)?;

    match nats
        .pl_reader::<SealedBearer>()
        .await
        .entries(&kv_prefix(BEARER_TOKENS_KEY_PREFIX)?)
        .await
    {
        Ok(collected) => Ok(CheckOutcome::fail(
            id,
            expected,
            format!(
                "entries() returned Ok with {} key(s) — the undecodable value was skipped",
                collected.len()
            ),
            "the fabric scan silently skipped an undecodable cohabiting value instead of failing closed",
        )),
        Err(FabricError::Decode { subject, .. }) if subject == garbage_key.as_str() => {
            Ok(CheckOutcome::pass(
                id,
                expected,
                format!("entries() failed closed with FabricError::Decode on {subject}"),
            ))
        }
        Err(FabricError::Decode { subject, .. }) => Ok(CheckOutcome::fail(
            id,
            expected,
            format!("decode error named a different key: {subject}"),
            "the fail-closed decode error did not name the garbage bearer key",
        )),
        Err(other) => Ok(CheckOutcome::fail(
            id,
            expected,
            format!("entries() errored with {other}"),
            "the fabric scan failed, but not with the expected FabricError::Decode",
        )),
    }
}

pub async fn directory_prefix_ignores_bearer() -> Result<CheckOutcome> {
    let id = CheckId::DirectoryPrefixIgnoresBearer;
    let expected = "a real PublishedLanguageReader scoped to identity/users/ does NOT pick up a bearer key \
                    sharing the bucket, and a reader scoped to identity/bearer_tokens/ does NOT pick up the \
                    directory key (cohabitation safety)";
    let anchor = Anchor::build().await?;
    let nats = FabricTestNats::start()
        .await
        .with_published_language()
        .await;
    let outcome = directory_prefix_inner(id, expected, &anchor, &nats).await;
    nats.shutdown().await;
    outcome
}

async fn directory_prefix_inner(
    id: CheckId,
    expected: &str,
    anchor: &Anchor,
    nats: &FabricTestNats,
) -> Result<CheckOutcome> {
    let plaintext = encode_entry(&human_entry())?;
    let sealed = anchor.seal(&SEAL_KEY_BYTES, TOKEN, &plaintext).await?;
    let bearer_key = kv_key(&bearer_token_kv_key(TOKEN))?;
    nats.pl_publisher::<SealedBearer>()
        .await
        .put(&bearer_key, &sealed)
        .await
        .map_err(fabric_err)?;

    let directory_key = kv_key(&format!(
        "{DIRECTORY_USERS_PREFIX}{}",
        uuid::Uuid::now_v7().simple()
    ))?;
    let directory_value = serde_json::json!({ "email": "ada@example.com" });
    nats.pl_publisher::<serde_json::Value>()
        .await
        .put(&directory_key, &directory_value)
        .await
        .map_err(fabric_err)?;

    let directory_view = nats
        .pl_reader::<serde_json::Value>()
        .await
        .entries(&kv_prefix(DIRECTORY_USERS_PREFIX)?)
        .await
        .map_err(fabric_err)?;

    if directory_view.contains_key(&bearer_key) {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "directory reader saw the bearer key",
            "the identity/users/ prefix leaked into the bearer key space — prefixes are not isolating",
        ));
    }
    if !directory_view.contains_key(&directory_key) {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "directory reader missed its own key",
            "the directory-prefixed reader did not read its own key",
        ));
    }

    let bearer_view = nats
        .pl_reader::<SealedBearer>()
        .await
        .entries(&kv_prefix(BEARER_TOKENS_KEY_PREFIX)?)
        .await
        .map_err(fabric_err)?;
    if !bearer_view.contains_key(&bearer_key) {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "bearer reader missed the bearer key",
            "the bearer-prefixed reader did not read the bearer key it published",
        ));
    }
    if bearer_view.contains_key(&directory_key) {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "bearer reader saw the directory key",
            "the bearer prefix leaked into the directory key space",
        ));
    }

    Ok(CheckOutcome::pass(
        id,
        expected,
        "the two prefixes cohabit the real PL bucket without cross-reading each other's keys",
    ))
}
