//! Bearer token validation via NATS KV.
//!
//! svc-auth validates bearer tokens by deriving the canonical KV key from the
//! plaintext token (via [`br_core_auth::bearer_token_key`]) and checking
//! whether that key exists in the NATS KV bucket `bearer_tokens`. svc-auth is
//! token-type-agnostic -- it does not care whether the token is a PAT, API
//! key, or anything else; the shared key derivation guarantees we hash in
//! lockstep with whichever service issued the token.

use br_core_auth::bearer_token_key;

/// Validates bearer tokens against the NATS KV bucket `bearer_tokens`.
pub struct BearerValidator {
    kv: async_nats::jetstream::kv::Store,
}

impl BearerValidator {
    pub fn new(kv: async_nats::jetstream::kv::Store) -> Self {
        Self { kv }
    }

    /// Check if a bearer token's hash exists in the KV bucket.
    /// Returns `Ok(true)` if recognized, `Ok(false)` if not found,
    /// `Err` on infrastructure failure.
    pub async fn is_valid(
        &self,
        token: &str,
    ) -> Result<bool, async_nats::error::Error<async_nats::jetstream::kv::EntryErrorKind>> {
        let key = bearer_token_key(token);
        match self.kv.get(&key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Health check: verify the KV bucket is reachable.
    pub async fn is_healthy(&self) -> bool {
        self.kv.status().await.is_ok()
    }
}
