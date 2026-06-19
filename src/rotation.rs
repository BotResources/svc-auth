use br_util_nats_fabric::Revision;
use uuid::Uuid;

use crate::refresh_store::{RefreshToken, RefreshTokenStore, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("refresh token reuse detected for family {0}; family revoked")]
    Reuse(Uuid),

    #[error("refresh token rotation failed against EPHEMERAL_AUTH: {0}")]
    Store(StoreError),
}

pub async fn rotate(
    store: &RefreshTokenStore,
    old: &RefreshToken,
    revision: Revision,
    new: &RefreshToken,
) -> Result<(), RotationError> {
    if old.used_at.is_some() {
        if let Err(e) = store.revoke_family(old.family_id).await {
            tracing::error!(error = %e, family_id = %old.family_id, "family revocation failed after reuse detection");
        }
        return Err(RotationError::Reuse(old.family_id));
    }

    store.store(new).await.map_err(RotationError::Store)?;

    match store.mark_used(old, new.id, revision).await {
        Ok(()) => Ok(()),
        Err(StoreError::Conflict(_)) => {
            if let Err(e) = store.revoke_family(old.family_id).await {
                tracing::error!(error = %e, family_id = %old.family_id, "family revocation failed after reuse detection");
            }
            Err(RotationError::Reuse(old.family_id))
        }
        Err(e) => Err(RotationError::Store(e)),
    }
}
