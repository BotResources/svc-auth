use br_util_nats_fabric::{EphemeralAuthStore, Fabric, FabricError, KvKey, Revision};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const REFRESH_PREFIX: &str = "refresh.";
const REVOKED_PREFIX: &str = "revoked.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub email: String,
    pub family_id: Uuid,
    pub used_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedFamily {
    pub revoked_at: DateTime<Utc>,
}

pub struct RefreshTokenStore {
    tokens: EphemeralAuthStore<RefreshToken>,
    revoked_families: EphemeralAuthStore<RevokedFamily>,
}

impl RefreshTokenStore {
    pub async fn open(fabric: &Fabric) -> Result<Self, StoreError> {
        let tokens = EphemeralAuthStore::<RefreshToken>::open(fabric)
            .await
            .map_err(StoreError::Open)?;
        let revoked_families = EphemeralAuthStore::<RevokedFamily>::open(fabric)
            .await
            .map_err(StoreError::Open)?;
        Ok(Self {
            tokens,
            revoked_families,
        })
    }

    pub async fn store(&self, token: &RefreshToken) -> Result<(), StoreError> {
        let key = refresh_key(token.id)?;
        self.tokens.put(&key, token).await.map_err(StoreError::Kv)
    }

    pub async fn find_by_id(
        &self,
        token_id: Uuid,
    ) -> Result<Option<(RefreshToken, Revision)>, StoreError> {
        let key = refresh_key(token_id)?;
        self.tokens
            .get_with_revision(&key)
            .await
            .map_err(StoreError::Kv)
    }

    pub async fn mark_used(
        &self,
        old: &RefreshToken,
        replaced_by: Uuid,
        revision: Revision,
    ) -> Result<(), StoreError> {
        let key = refresh_key(old.id)?;
        let mut token = old.clone();
        token.used_at = Some(Utc::now());
        token.replaced_by = Some(replaced_by);

        match self.tokens.update_if(&key, &token, revision).await {
            Ok(()) => Ok(()),
            Err(FabricError::RevisionConflict { .. }) => Err(StoreError::Conflict(old.id)),
            Err(e) => Err(StoreError::Kv(e)),
        }
    }

    pub async fn revoke_family(&self, family_id: Uuid) -> Result<(), StoreError> {
        let key = revoked_key(family_id)?;
        let entry = RevokedFamily {
            revoked_at: Utc::now(),
        };
        self.revoked_families
            .put(&key, &entry)
            .await
            .map_err(StoreError::Kv)
    }

    pub async fn is_family_revoked(&self, family_id: Uuid) -> bool {
        match revoked_key(family_id) {
            Ok(key) => matches!(
                self.revoked_families.get_with_revision(&key).await,
                Ok(Some(_))
            ),
            Err(_) => false,
        }
    }

    pub async fn is_healthy(&self) -> bool {
        self.tokens.status().await.is_ok()
    }
}

fn refresh_key(token_id: Uuid) -> Result<KvKey, StoreError> {
    KvKey::new(format!("{REFRESH_PREFIX}{token_id}")).map_err(|e| StoreError::Key(e.to_string()))
}

fn revoked_key(family_id: Uuid) -> Result<KvKey, StoreError> {
    KvKey::new(format!("{REVOKED_PREFIX}{family_id}")).map_err(|e| StoreError::Key(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("opening the EPHEMERAL_AUTH store failed: {0}")]
    Open(FabricError),

    #[error("EPHEMERAL_AUTH KV error: {0}")]
    Kv(FabricError),

    #[error("invalid KV key: {0}")]
    Key(String),

    #[error("refresh token rotation lost the compare-and-swap race: {0}")]
    Conflict(Uuid),
}
