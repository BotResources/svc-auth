//! Self-contained JWT service for svc-auth.
//!
//! Signs and verifies internal JWTs. Zero workspace dependencies.
//! Access tokens carry `sub: email`. Refresh tokens carry `sub: email`
//! and `jti: token_id`.

use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

/// JWT claims for refresh tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String,
    pub jti: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    access_ttl_secs: u64,
    refresh_ttl_secs: u64,
}

impl JwtService {
    pub fn new(secret: &str, issuer: &str, access_ttl_secs: u64, refresh_ttl_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer: issuer.to_string(),
            access_ttl_secs,
            refresh_ttl_secs,
        }
    }

    pub fn access_ttl_secs(&self) -> u64 {
        self.access_ttl_secs
    }

    pub fn refresh_ttl_secs(&self) -> u64 {
        self.refresh_ttl_secs
    }

    /// Sign an access token with `sub: email`.
    pub fn sign_access_token(&self, email: &str) -> Result<String, String> {
        let now = Utc::now().timestamp();
        let claims = AccessClaims {
            sub: email.to_string(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + self.access_ttl_secs as i64,
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| format!("failed to sign access token: {e}"))
    }

    /// Verify an access token. Returns claims if valid.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, JwtError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["sub", "iss", "iat", "exp"]);

        let token_data =
            decode::<AccessClaims>(token, &self.decoding_key, &validation).map_err(|e| match e
                .kind()
            {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::Invalid(e.to_string()),
            })?;

        Ok(token_data.claims)
    }

    /// Sign a refresh token with `sub: email` and `jti: token_id`.
    /// Returns `(jwt_string, token_id, token_hash)`.
    pub fn sign_refresh_token(&self, email: &str) -> Result<(String, Uuid, Vec<u8>), String> {
        let token_id = Uuid::now_v7();
        let now = Utc::now().timestamp();
        let claims = RefreshClaims {
            sub: email.to_string(),
            jti: token_id.to_string(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + self.refresh_ttl_secs as i64,
        };
        let jwt = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| format!("failed to sign refresh token: {e}"))?;

        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(jwt.as_bytes()).to_vec();

        Ok((jwt, token_id, hash))
    }

    /// Verify a refresh token. Returns claims if valid.
    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshClaims, JwtError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["sub", "jti", "iss", "iat", "exp"]);

        let token_data =
            decode::<RefreshClaims>(token, &self.decoding_key, &validation).map_err(|e| match e
                .kind()
            {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::Invalid(e.to_string()),
            })?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token expired")]
    Expired,

    #[error("invalid token: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> JwtService {
        JwtService::new(
            "test-secret-key-at-least-32-chars!",
            "test-issuer",
            900,
            604_800,
        )
    }

    #[test]
    fn sign_and_verify_access_token() {
        let svc = test_service();
        let token = svc.sign_access_token("alice@example.com").unwrap();
        let claims = svc.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, "alice@example.com");
        assert_eq!(claims.iss, "test-issuer");
    }

    #[test]
    fn verify_access_token_wrong_secret_fails() {
        let svc = test_service();
        let token = svc.sign_access_token("alice@example.com").unwrap();

        let other = JwtService::new(
            "other-secret-key-at-least-32-chars!",
            "test-issuer",
            900,
            604_800,
        );
        assert!(other.verify_access_token(&token).is_err());
    }

    #[test]
    fn sign_and_verify_refresh_token() {
        let svc = test_service();
        let (token, token_id, hash) = svc.sign_refresh_token("alice@example.com").unwrap();
        assert!(!hash.is_empty());

        let claims = svc.verify_refresh_token(&token).unwrap();
        assert_eq!(claims.sub, "alice@example.com");
        assert_eq!(claims.jti, token_id.to_string());
    }

    #[test]
    fn verify_malformed_token_fails() {
        let svc = test_service();
        assert!(svc.verify_access_token("not-a-jwt").is_err());
    }

    #[test]
    fn expired_access_token_returns_expired_error() {
        let svc = test_service();
        let now = chrono::Utc::now().timestamp();
        let claims = AccessClaims {
            sub: "alice@example.com".to_string(),
            iss: "test-issuer".to_string(),
            iat: now - 300,
            exp: now - 120,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret-key-at-least-32-chars!"),
        )
        .unwrap();
        match svc.verify_access_token(&token) {
            Err(JwtError::Expired) => {}
            other => panic!("expected Expired, got {:?}", other),
        }
    }
}
