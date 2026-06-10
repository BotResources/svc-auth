//! Multi-provider OIDC id_token verification with automatic JWKS refresh.
//!
//! Auto-discovers providers from OIDC_*_DISCOVERY_URL env vars at startup.
//! Routes incoming id_tokens to the correct provider by matching the `iss` claim.
//! JWKS keys are cached per-provider and refreshed on cache miss (unknown kid).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use tokio::sync::RwLock;

use crate::config::OidcProviderConfig;

/// Claims extracted from a verified OIDC id_token.
pub struct OidcClaims {
    pub email: String,
}

/// Multi-provider OIDC validator. Routes id_tokens by issuer.
pub struct OidcValidator {
    providers: Vec<OidcProvider>,
}

/// OIDC discovery document (only the fields we need).
#[derive(serde::Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// A single configured OIDC provider with its own JWKS cache.
struct OidcProvider {
    name: String,
    issuer: String,
    client_id: String,
    email_claim: String,
    jwks_uri: String,
    jwks: RwLock<JwkSet>,
    last_refresh: std::sync::Mutex<Instant>,
    refresh_cooldown: Duration,
    http_client: reqwest::Client,
}

impl OidcValidator {
    /// Initialize all OIDC providers by fetching their discovery documents and JWKS.
    ///
    /// `refresh_cooldown` bounds how often a provider's JWKS is re-fetched on
    /// unknown-`kid` misses (re-fetch storms from invalid tokens).
    pub async fn discover(
        configs: &[OidcProviderConfig],
        refresh_cooldown: Duration,
    ) -> Result<Self, String> {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut providers = Vec::with_capacity(configs.len());

        for config in configs {
            let discovery_url = format!(
                "{}/.well-known/openid-configuration",
                config.discovery_url.trim_end_matches('/')
            );

            let discovery: DiscoveryDocument = http_client
                .get(&discovery_url)
                .send()
                .await
                .map_err(|e| format!("OIDC discovery failed for {}: {e}", config.name))?
                .json()
                .await
                .map_err(|e| format!("OIDC discovery parse failed for {}: {e}", config.name))?;

            let initial_jwks: JwkSet = http_client
                .get(&discovery.jwks_uri)
                .send()
                .await
                .map_err(|e| format!("JWKS fetch failed for {}: {e}", config.name))?
                .json()
                .await
                .map_err(|e| format!("JWKS parse failed for {}: {e}", config.name))?;

            tracing::info!(
                provider = %config.name,
                issuer = %discovery.issuer,
                key_count = initial_jwks.keys.len(),
                "OIDC provider discovered, JWKS loaded"
            );

            providers.push(OidcProvider {
                name: config.name.clone(),
                issuer: discovery.issuer,
                client_id: config.client_id.clone(),
                email_claim: config.email_claim.clone(),
                jwks_uri: discovery.jwks_uri,
                jwks: RwLock::new(initial_jwks),
                last_refresh: std::sync::Mutex::new(Instant::now()),
                refresh_cooldown,
                http_client: http_client.clone(),
            });
        }

        Ok(Self { providers })
    }

    /// Create an empty validator (no providers). Only reachable in local
    /// environments (config rejects the absence of providers elsewhere);
    /// every id_token verification against it fails.
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Verify an id_token against the matching provider (by issuer).
    pub async fn verify_id_token(&self, id_token: &str) -> Result<OidcClaims, String> {
        // Peek at the unverified issuer to route to the correct provider.
        let payload = decode_jwt_payload(id_token)?;
        let issuer = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or("no iss claim in token")?
            .to_string();

        let provider = self
            .providers
            .iter()
            .find(|p| p.issuer == issuer)
            .ok_or_else(|| format!("no OIDC provider configured for issuer: {issuer}"))?;

        // Decode header to get kid.
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| format!("invalid token header: {e}"))?;

        // Resolve the signing key: by kid if present, single-key fallback otherwise.
        let jwk = match &header.kid {
            Some(kid) => provider.resolve_key(kid).await?,
            None => provider.resolve_single_key().await?,
        };

        // Use algorithm from the JWK; fall back to JWT header.
        let alg = jwk
            .common
            .key_algorithm
            .and_then(key_algorithm_to_jwt)
            .unwrap_or(header.alg);

        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).map_err(|e| {
            let kid = jwk.common.key_id.as_deref().unwrap_or("unknown");
            format!("invalid JWK for kid {kid}: {e}")
        })?;

        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.set_issuer(&[&provider.issuer]);
        validation.set_audience(&[&provider.client_id]);

        jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(id_token, &key, &validation)
            .map_err(|e| format!("id_token verification failed for {}: {e}", provider.name))?;

        let email = extract_email_from_payload(&payload, &provider.email_claim)?;

        Ok(OidcClaims { email })
    }
}

impl OidcProvider {
    /// Look up a JWK by kid. On cache miss, re-fetches the JWKS endpoint.
    async fn resolve_key(&self, kid: &str) -> Result<jsonwebtoken::jwk::Jwk, String> {
        // Fast path: key already cached.
        {
            let keys = self.jwks.read().await;
            if let Some(jwk) = find_key(&keys, kid) {
                return Ok(jwk.clone());
            }
        }

        tracing::info!(provider = %self.name, kid, "kid not in cache, refreshing JWKS");

        self.refresh_jwks().await?;

        let keys = self.jwks.read().await;
        find_key(&keys, kid).cloned().ok_or_else(|| {
            format!(
                "kid '{kid}' not found in JWKS for provider {} (even after refresh)",
                self.name
            )
        })
    }

    /// Fallback when the JWT has no kid: use the only key if the JWKS has exactly one.
    async fn resolve_single_key(&self) -> Result<jsonwebtoken::jwk::Jwk, String> {
        let keys = self.jwks.read().await;
        match keys.keys.len() {
            1 => Ok(keys.keys[0].clone()),
            0 => Err(format!("JWKS for provider {} has no keys", self.name)),
            n => Err(format!(
                "id_token has no kid and JWKS for provider {} has {n} keys — cannot pick one",
                self.name
            )),
        }
    }

    async fn refresh_jwks(&self) -> Result<(), String> {
        {
            let last = self.last_refresh.lock().unwrap();
            if last.elapsed() < self.refresh_cooldown {
                tracing::debug!(provider = %self.name, "JWKS refresh skipped (cooldown)");
                return Ok(());
            }
        }

        let new_keys: JwkSet = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed for {}: {e}", self.name))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed for {}: {e}", self.name))?;

        let key_count = new_keys.keys.len();

        *self.jwks.write().await = new_keys;
        *self.last_refresh.lock().unwrap() = Instant::now();

        tracing::info!(provider = %self.name, key_count, "JWKS keys refreshed");

        Ok(())
    }
}

fn find_key<'a>(jwks: &'a JwkSet, kid: &str) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    jwks.keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
}

fn key_algorithm_to_jwt(ka: jsonwebtoken::jwk::KeyAlgorithm) -> Option<jsonwebtoken::Algorithm> {
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::jwk::KeyAlgorithm as KA;
    match ka {
        KA::RS256 => Some(Algorithm::RS256),
        KA::RS384 => Some(Algorithm::RS384),
        KA::RS512 => Some(Algorithm::RS512),
        KA::ES256 => Some(Algorithm::ES256),
        KA::ES384 => Some(Algorithm::ES384),
        KA::PS256 => Some(Algorithm::PS256),
        KA::PS384 => Some(Algorithm::PS384),
        KA::PS512 => Some(Algorithm::PS512),
        KA::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

/// Decode the JWT payload (second segment) into a generic JSON map.
/// Does NOT verify the signature.
fn decode_jwt_payload(token: &str) -> Result<HashMap<String, serde_json::Value>, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid token format".to_string());
    }

    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "invalid token encoding".to_string())?;

    serde_json::from_slice(&bytes).map_err(|_| "invalid token payload".to_string())
}

/// Extract email from the decoded JWT payload using the configured claim name.
/// Falls back to "email" if the configured claim is missing.
fn extract_email_from_payload(
    payload: &HashMap<String, serde_json::Value>,
    email_claim: &str,
) -> Result<String, String> {
    // Try the configured claim first, fall back to "email".
    let email = payload
        .get(email_claim)
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("email").and_then(|v| v.as_str()))
        .unwrap_or_default()
        .to_string();

    if email.is_empty() {
        return Err(format!(
            "no '{email_claim}' or 'email' claim found in id_token"
        ));
    }

    Ok(email)
}
