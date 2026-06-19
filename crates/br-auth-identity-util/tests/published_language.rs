use br_auth_contract::{BearerEntry, BearerSealKey, SealedBearer, bearer_token_kv_key, open};
use br_auth_identity_util::BearerPublisher;
use br_core_kernel::{Actor, ServiceAccountId, UserId};
use br_test_harness::FabricTestNats;
use br_util_nats_fabric::{KvKey, KvPrefix};
use uuid::Uuid;

const HUMAN_TOKEN: &str = "human-bearer-token-itest";
const SERVICE_TOKEN: &str = "service-bearer-token-itest";

fn seal_key() -> BearerSealKey {
    let bytes = [9u8; 32];
    BearerSealKey::from_bytes(&bytes).unwrap()
}

fn human_entry() -> BearerEntry {
    BearerEntry {
        actor: Actor::Human(UserId::from(Uuid::from_u128(0x42))),
        token_id: Uuid::from_u128(0x7),
    }
}

fn service_entry() -> BearerEntry {
    BearerEntry {
        actor: Actor::Service(ServiceAccountId::from(Uuid::from_u128(0x99))),
        token_id: Uuid::from_u128(0x1),
    }
}

fn kv_key(token: &str) -> KvKey {
    KvKey::new(bearer_token_kv_key(token)).unwrap()
}

fn bearer_prefix() -> KvPrefix {
    KvPrefix::new(br_auth_contract::BEARER_TOKENS_KEY_PREFIX).unwrap()
}

#[tokio::test]
#[ignore = "real-infra: needs `nats-server` on PATH"]
async fn put_bearer_is_read_back_and_opened_then_delete_bearer_removes_the_key() {
    let nats = FabricTestNats::start()
        .await
        .with_published_language()
        .await;

    let publisher = BearerPublisher::open(nats.fabric(), seal_key())
        .await
        .expect("open BearerPublisher over the real fabric");

    for (token, entry) in [
        (HUMAN_TOKEN, human_entry()),
        (SERVICE_TOKEN, service_entry()),
    ] {
        publisher
            .put_bearer(token, &entry)
            .await
            .expect("put_bearer over the real PL bucket");

        let reader = nats.pl_reader::<SealedBearer>().await;
        let read_back = reader
            .get(&kv_key(token))
            .await
            .expect("read the sealed bearer back")
            .expect("the published bearer key is present after put_bearer");

        let opened = open(&seal_key(), token, &read_back).expect("open the PL-transported bearer");
        assert_eq!(
            opened, entry,
            "the read-back bearer opens to the original entry"
        );

        let collected = reader
            .entries(&bearer_prefix())
            .await
            .expect("scan the bearer prefix");
        assert_eq!(
            collected.get(&kv_key(token)),
            Some(&read_back),
            "the bearer key appears under its contract prefix"
        );

        publisher
            .delete_bearer(token)
            .await
            .expect("delete_bearer over the real PL bucket");

        let after_delete = nats
            .pl_reader::<SealedBearer>()
            .await
            .get(&kv_key(token))
            .await
            .expect("read after delete");
        assert!(
            after_delete.is_none(),
            "delete_bearer removed the key; revocation is observable"
        );
    }

    nats.shutdown().await;
}
