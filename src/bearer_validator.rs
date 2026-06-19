use br_auth_contract::{BearerEntry, BearerSealKey, SealedBearer, bearer_token_kv_key, open};
use br_util_nats_fabric::{Fabric, FabricError, KvKey, PublishedLanguageReader};

const HEALTH_PROBE_KEY: &str = "identity/bearer_tokens/__health_probe__";

#[derive(Debug, thiserror::Error)]
pub enum BearerValidatorError {
    #[error("opening the PUBLISHED_LANGUAGE bearer reader failed: {0}")]
    Open(FabricError),

    #[error("the presented bearer is not a valid KV key: {0}")]
    Key(String),

    #[error("reading the sealed bearer from PUBLISHED_LANGUAGE failed: {0}")]
    Read(FabricError),
}

pub struct BearerValidator {
    reader: PublishedLanguageReader<SealedBearer>,
    key: BearerSealKey,
}

impl BearerValidator {
    pub async fn open(fabric: &Fabric, key: BearerSealKey) -> Result<Self, BearerValidatorError> {
        let reader = PublishedLanguageReader::<SealedBearer>::open(fabric)
            .await
            .map_err(BearerValidatorError::Open)?;
        Ok(Self { reader, key })
    }

    pub async fn resolve(&self, token: &str) -> Result<Option<BearerEntry>, BearerValidatorError> {
        let kv_key = KvKey::new(bearer_token_kv_key(token))
            .map_err(|e| BearerValidatorError::Key(e.to_string()))?;
        match self.reader.get(&kv_key).await {
            Ok(Some(sealed)) => Ok(open(&self.key, token, &sealed).ok()),
            Ok(None) => Ok(None),
            Err(e) => Err(BearerValidatorError::Read(e)),
        }
    }

    pub async fn is_healthy(&self) -> bool {
        match KvKey::new(HEALTH_PROBE_KEY) {
            Ok(probe) => self.reader.get(&probe).await.is_ok(),
            Err(_) => false,
        }
    }
}
