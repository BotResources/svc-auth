//! Multi-provider OIDC id_token verification using `openidconnect`.
//!
//! Auto-discovers providers from OIDC_*_DISCOVERY_URL env vars at startup.
//! Routes incoming id_tokens to the correct provider by matching the `iss` claim.
//! Each provider has its own JWKS cache managed by the openidconnect crate.
//!
//! After signature verification, email is extracted from the raw JWT payload
//! using the configured claim name (e.g. `preferred_username` for Entra).

use std::collections::HashMap;
use std::str::FromStr;

use openidconnect::core::{CoreClient, CoreGenderClaim, CoreProviderMetadata};
use openidconnect::{
    ClientId, EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
};

use crate::config::OidcProviderConfig;

/// CoreClient after OIDC discovery has populated endpoints.
type DiscoveredClient = CoreClient<
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointMaybeSet, // HasTokenUrl
    EndpointMaybeSet, // HasUserInfoUrl
>;

/// Claims extracted from a verified OIDC id_token.
pub struct OidcClaims {
    pub email: String,
}

/// Multi-provider OIDC validator. Routes id_tokens by issuer.
pub struct OidcValidator {
    providers: Vec<OidcProvider>,
}

/// A single configured OIDC provider with its openidconnect client.
pub struct OidcProvider {
    pub name: String,
    pub issuer: String,
    client: DiscoveredClient,
    email_claim: String,
}

impl OidcValidator {
    /// Initialize all OIDC providers by fetching their discovery documents.
    /// This is async because each provider requires an HTTP fetch.
    pub async fn discover(configs: &[OidcProviderConfig]) -> Result<Self, String> {
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut providers = Vec::with_capacity(configs.len());

        for config in configs {
            let issuer_url = IssuerUrl::new(config.discovery_url.clone())
                .map_err(|e| format!("invalid discovery URL for {}: {e}", config.name))?;

            let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
                .await
                .map_err(|e| format!("OIDC discovery failed for {}: {e}", config.name))?;

            let issuer = metadata.issuer().as_str().to_string();

            let client = DiscoveredClient::from_provider_metadata(
                metadata,
                ClientId::new(config.client_id.clone()),
                None,
            );

            providers.push(OidcProvider {
                name: config.name.clone(),
                issuer,
                client,
                email_claim: config.email_claim.clone(),
            });

            tracing::info!(
                provider = %config.name,
                "OIDC provider discovered successfully"
            );
        }

        Ok(Self { providers })
    }

    /// Create an empty validator (no providers). Used when ALLOW_INSECURE is true
    /// and no providers are configured.
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

        // Parse the raw JWT string into an IdToken.
        let token: openidconnect::IdToken<
            EmptyAdditionalClaims,
            CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        > = openidconnect::IdToken::from_str(id_token)
            .map_err(|e| format!("invalid id_token format: {e}"))?;

        // Verify signature, issuer, audience. Skip nonce check because the
        // frontend handled the PKCE flow and we only receive the id_token.
        let verifier = provider.client.id_token_verifier();
        token
            .claims(&verifier, |_nonce: Option<&openidconnect::Nonce>| Ok(()))
            .map_err(|e| format!("id_token verification failed for {}: {e}", provider.name))?;

        // Signature verified — now extract the configured email claim from the
        // raw payload. The openidconnect crate doesn't expose non-standard claims
        // like preferred_username, so we read from the decoded payload directly.
        let email = extract_email_from_payload(&payload, &provider.email_claim)?;

        Ok(OidcClaims { email })
    }

    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }
}

/// Parse id_token claims without verification (ALLOW_INSECURE mode only).
pub fn parse_insecure_claims(token: &str) -> Result<OidcClaims, String> {
    let payload = decode_jwt_payload(token)?;

    // preferred_username takes priority over email (Entra pattern).
    let email = payload
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("email").and_then(|v| v.as_str()))
        .unwrap_or_default()
        .to_string();

    if email.is_empty() {
        return Err("no email found in id_token claims".to_string());
    }

    Ok(OidcClaims { email })
}

/// Decode the JWT payload (second segment) into a generic JSON map.
/// Does NOT verify the signature — call this only after openidconnect
/// has verified the token, or in ALLOW_INSECURE mode.
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
