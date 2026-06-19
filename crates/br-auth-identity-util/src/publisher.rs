use br_auth_contract::{BearerEntry, BearerSealKey, SealedBearer, bearer_token_kv_key, seal};
use br_util_nats_fabric::{Fabric, KvKey, PublishedLanguagePublisher};

use crate::error::BearerPublishError;

pub struct BearerPublisher {
    publisher: PublishedLanguagePublisher<SealedBearer>,
    key: BearerSealKey,
}

impl BearerPublisher {
    pub async fn open(fabric: &Fabric, key: BearerSealKey) -> Result<Self, BearerPublishError> {
        let publisher = PublishedLanguagePublisher::open(fabric)
            .await
            .map_err(|e| BearerPublishError::Bind(e.to_string()))?;
        Ok(Self { publisher, key })
    }

    pub async fn put_bearer(
        &self,
        token: &str,
        entry: &BearerEntry,
    ) -> Result<(), BearerPublishError> {
        let sealed =
            seal(&self.key, token, entry).map_err(|e| BearerPublishError::Seal(e.to_string()))?;
        let kv_key = bearer_kv_key(token)?;
        self.publisher
            .put(&kv_key, &sealed)
            .await
            .map_err(|e| BearerPublishError::Put(e.to_string()))
    }

    pub async fn delete_bearer(&self, token: &str) -> Result<(), BearerPublishError> {
        let kv_key = bearer_kv_key(token)?;
        self.publisher
            .retract(&kv_key)
            .await
            .map_err(|e| BearerPublishError::Delete(e.to_string()))
    }
}

fn bearer_kv_key(token: &str) -> Result<KvKey, BearerPublishError> {
    KvKey::new(bearer_token_kv_key(token)).map_err(|e| BearerPublishError::Key(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use br_auth_contract::open;
    use br_core_kernel::{Actor, ServiceAccountId, UserId};
    use uuid::Uuid;

    const TOKEN: &str = "bearer-token-under-test";
    const OTHER_TOKEN: &str = "a-different-bearer-token";

    fn seal_key() -> BearerSealKey {
        let bytes = [7u8; 32];
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

    #[test]
    fn put_bearer_seals_a_human_entry_recoverable_by_open_at_the_contract_key() {
        let key = seal_key();
        let entry = human_entry();
        let sealed = seal(&key, TOKEN, &entry).unwrap();

        let kv_key = bearer_kv_key(TOKEN).unwrap();
        assert_eq!(kv_key.as_str(), bearer_token_kv_key(TOKEN));

        let opened = open(&key, TOKEN, &sealed).unwrap();
        assert_eq!(opened, entry);
    }

    #[test]
    fn put_bearer_seals_a_service_entry_recoverable_by_open_at_the_contract_key() {
        let key = seal_key();
        let entry = service_entry();
        let sealed = seal(&key, TOKEN, &entry).unwrap();

        let kv_key = bearer_kv_key(TOKEN).unwrap();
        assert_eq!(kv_key.as_str(), bearer_token_kv_key(TOKEN));

        let opened = open(&key, TOKEN, &sealed).unwrap();
        assert_eq!(opened, entry);
    }

    #[test]
    fn a_bearer_sealed_for_one_token_does_not_open_as_another() {
        let key = seal_key();
        let entry = human_entry();
        let sealed = seal(&key, TOKEN, &entry).unwrap();

        assert!(
            open(&key, OTHER_TOKEN, &sealed).is_err(),
            "the token is the sole AAD: a bearer published for one token cannot be opened as another"
        );

        let key_a = bearer_kv_key(TOKEN).unwrap();
        let key_b = bearer_kv_key(OTHER_TOKEN).unwrap();
        assert_eq!(key_a.as_str(), bearer_token_kv_key(TOKEN));
        assert_ne!(
            key_a.as_str(),
            key_b.as_str(),
            "the token is also the sole KV-key source: distinct tokens land on distinct keys"
        );
    }

    #[test]
    fn the_kv_key_lives_under_the_contract_bearer_prefix() {
        let kv_key = bearer_kv_key(TOKEN).unwrap();
        assert!(
            kv_key
                .as_str()
                .starts_with(br_auth_contract::BEARER_TOKENS_KEY_PREFIX)
        );
    }
}
