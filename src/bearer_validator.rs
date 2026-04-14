//! Bearer token validation via NATS KV.
//!
//! svc-auth validates bearer tokens by computing SHA-256(token) and checking
//! whether the hash exists as a key in the NATS KV bucket `bearer_tokens`.
//! svc-auth is token-type-agnostic -- it does not care whether the token is
//! a PAT, API Key, or anything else.

use sha2::{Digest, Sha256};

/// Validates bearer tokens against the NATS KV bucket `bearer_tokens`.
pub struct BearerValidator {
    kv: async_nats::jetstream::kv::Store,
}

impl BearerValidator {
    pub fn new(kv: async_nats::jetstream::kv::Store) -> Self {
        Self { kv }
    }

    /// Check if a bearer token's hash exists in the KV bucket.
    /// Returns `true` if the token is recognized, `false` if not found or
    /// on any error (fail-open to anonymous).
    pub async fn is_valid(&self, token: &str) -> bool {
        let hash = hash_bearer(token);
        match self.kv.get(&hash).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "NATS KV bearer_tokens lookup failed; treating as anonymous"
                );
                false
            }
        }
    }

    /// Health check: verify the KV bucket is reachable.
    pub async fn is_healthy(&self) -> bool {
        self.kv.status().await.is_ok()
    }
}

/// Compute the hex-encoded SHA-256 hash of a bearer token.
/// This must match the hash format used by svc-identity when publishing
/// to the `bearer_tokens` KV bucket.
fn hash_bearer(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hex_encode(&hash)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bearer_produces_64_char_hex_string() {
        let hash = hash_bearer("hsh_validtoken1234567890abcdef");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_bearer_is_deterministic() {
        let h1 = hash_bearer("test_token");
        let h2 = hash_bearer("test_token");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_tokens_produce_different_hashes() {
        let h1 = hash_bearer("token_a");
        let h2 = hash_bearer("token_b");
        assert_ne!(h1, h2);
    }
}
