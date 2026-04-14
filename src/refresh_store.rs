//! Refresh token store backed by NATS KV.
//!
//! Uses two KV buckets:
//! - `auth_refresh_tokens` — stores refresh token data, TTL = refresh token lifetime
//! - `auth_revoked_families` — blocklist of revoked families, TTL = refresh token lifetime
//!
//! svc-auth has zero database dependencies. NATS KV TTL auto-expires tokens.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A refresh token stored in NATS KV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub email: String,
    pub token_hash: Vec<u8>,
    pub family_id: Uuid,
    pub used_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

pub struct RefreshTokenStore {
    tokens: async_nats::jetstream::kv::Store,
    revoked_families: async_nats::jetstream::kv::Store,
}

impl RefreshTokenStore {
    pub fn new(
        tokens: async_nats::jetstream::kv::Store,
        revoked_families: async_nats::jetstream::kv::Store,
    ) -> Self {
        Self {
            tokens,
            revoked_families,
        }
    }

    /// Insert a new refresh token.
    pub async fn store(&self, token: &RefreshToken) -> Result<(), StoreError> {
        let value = serde_json::to_vec(token).map_err(|e| StoreError::Serialize(e.to_string()))?;
        self.tokens
            .put(token.id.to_string(), value.into())
            .await
            .map_err(|e| StoreError::Nats(e.to_string()))?;
        Ok(())
    }

    /// Find a refresh token by its UUID (the `jti` claim).
    /// Returns the token and its KV revision (for CAS on update).
    pub async fn find_by_id(
        &self,
        token_id: Uuid,
    ) -> Result<Option<(RefreshToken, u64)>, StoreError> {
        match self.tokens.entry(token_id.to_string()).await {
            Ok(Some(entry)) => {
                let token: RefreshToken = serde_json::from_slice(&entry.value)
                    .map_err(|e| StoreError::Serialize(e.to_string()))?;
                Ok(Some((token, entry.revision)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Nats(e.to_string())),
        }
    }

    /// Mark a refresh token as used and record its replacement.
    /// Uses CAS (compare-and-swap via revision) to prevent race conditions.
    pub async fn mark_used(
        &self,
        token_id: Uuid,
        replaced_by: Uuid,
        revision: u64,
    ) -> Result<(), StoreError> {
        let (mut token, _) = self
            .find_by_id(token_id)
            .await?
            .ok_or_else(|| StoreError::NotFound(token_id.to_string()))?;

        token.used_at = Some(Utc::now());
        token.replaced_by = Some(replaced_by);

        let value = serde_json::to_vec(&token).map_err(|e| StoreError::Serialize(e.to_string()))?;
        self.tokens
            .update(token_id.to_string(), value.into(), revision)
            .await
            .map_err(|e| StoreError::Nats(e.to_string()))?;
        Ok(())
    }

    /// Revoke a token family by adding it to the revoked families blocklist.
    pub async fn revoke_family(&self, family_id: Uuid) -> Result<(), StoreError> {
        let timestamp = Utc::now().to_rfc3339();
        self.revoked_families
            .put(family_id.to_string(), timestamp.into())
            .await
            .map_err(|e| StoreError::Nats(e.to_string()))?;
        Ok(())
    }

    /// Check if a token family has been revoked.
    pub async fn is_family_revoked(&self, family_id: Uuid) -> bool {
        matches!(
            self.revoked_families.get(family_id.to_string()).await,
            Ok(Some(_))
        )
    }

    /// Health check: verify both KV buckets are reachable.
    pub async fn is_healthy(&self) -> bool {
        self.tokens.status().await.is_ok() && self.revoked_families.status().await.is_ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("NATS KV error: {0}")]
    Nats(String),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("token not found: {0}")]
    NotFound(String),
}

