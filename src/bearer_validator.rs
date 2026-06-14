use br_core_auth::{BearerTokenEntry, bearer_token_key};

pub struct BearerValidator {
    kv: async_nats::jetstream::kv::Store,
}

impl BearerValidator {
    pub fn new(kv: async_nats::jetstream::kv::Store) -> Self {
        Self { kv }
    }

    pub async fn is_valid(
        &self,
        token: &str,
    ) -> Result<bool, async_nats::error::Error<async_nats::jetstream::kv::EntryErrorKind>> {
        let key = bearer_token_key(token);
        match self.kv.get(&key).await {
            Ok(Some(bytes)) => Ok(serde_json::from_slice::<BearerTokenEntry>(&bytes).is_ok()),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn is_healthy(&self) -> bool {
        self.kv.status().await.is_ok()
    }
}
