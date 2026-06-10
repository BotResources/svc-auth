//! Configuration loading from environment variables.
//!
//! svc-auth has zero workspace dependencies. All configuration is self-contained.
//!
//! OIDC providers are auto-detected by scanning for OIDC_*_DISCOVERY_URL env vars.
//! Each provider needs: OIDC_{NAME}_DISCOVERY_URL, OIDC_{NAME}_CLIENT_ID,
//! and optionally OIDC_{NAME}_EMAIL_CLAIM (default: "email").

/// Application configuration loaded from environment variables.
pub struct AppConfig {
    pub nats_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
    pub port: u16,
    pub environment: Environment,
    pub secure_cookies: bool,
    pub auth_check_silent_refresh: bool,
    pub oidc_providers: Vec<OidcProviderConfig>,
    /// Minimum delay between two JWKS re-fetches for the same provider
    /// (unknown-`kid` storm protection). Default 60s; e2e suites lower it
    /// to exercise the cooldown without stalling.
    pub jwks_refresh_cooldown_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    Local,
    Dev,
    Test,
    Prod,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Dev => write!(f, "dev"),
            Self::Test => write!(f, "test"),
            Self::Prod => write!(f, "prod"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    pub name: String,
    pub discovery_url: String,
    pub client_id: String,
    pub email_claim: String,
}

impl AppConfig {
    /// Load configuration from environment variables. Fails fast on missing
    /// required variables.
    pub fn from_env() -> Result<Self, String> {
        let nats_url = required_env("NATS_URL")?;
        let jwt_secret = required_env("JWT_SECRET")?;

        let jwt_issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "svc-auth".to_string());
        let access_token_ttl = parse_u64_env("JWT_ACCESS_TOKEN_TTL", 900);
        let refresh_token_ttl = parse_u64_env("JWT_REFRESH_TOKEN_TTL", 604_800);
        let port = parse_u16_env("PORT", 8002);

        let environment = match std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "local".to_string())
            .as_str()
        {
            "dev" => Environment::Dev,
            "test" => Environment::Test,
            "prod" => Environment::Prod,
            _ => Environment::Local,
        };

        let secure_cookies = parse_bool_env("SECURE_COOKIES", true);

        let jwks_refresh_cooldown_secs = parse_u64_env("JWKS_REFRESH_COOLDOWN_SECONDS", 60);

        // Default true = preserves legacy nginx/OpenResty behavior. Set to
        // false behind k8s ingress middlewares (Traefik ForwardAuth,
        // nginx-ingress auth-url, Envoy ExternalAuthz) that cannot forward
        // Set-Cookie from auth responses. See issue #1.
        let auth_check_silent_refresh = parse_bool_env("AUTH_CHECK_SILENT_REFRESH", true);

        let oidc_providers = discover_oidc_providers(&environment)?;

        Ok(Self {
            nats_url,
            jwt_secret,
            jwt_issuer,
            access_token_ttl,
            refresh_token_ttl,
            port,
            environment,
            secure_cookies,
            auth_check_silent_refresh,
            oidc_providers,
            jwks_refresh_cooldown_secs,
        })
    }
}

/// Auto-detect OIDC providers by scanning for OIDC_*_DISCOVERY_URL env vars.
fn discover_oidc_providers(environment: &Environment) -> Result<Vec<OidcProviderConfig>, String> {
    let suffix = "_DISCOVERY_URL";
    let prefix = "OIDC_";

    let mut providers = Vec::new();

    for (key, discovery_url) in std::env::vars() {
        if !key.starts_with(prefix) || !key.ends_with(suffix) {
            continue;
        }
        if discovery_url.is_empty() {
            continue;
        }

        // Extract provider name: OIDC_ENTRA_DISCOVERY_URL -> ENTRA
        let name = &key[prefix.len()..key.len() - suffix.len()];
        if name.is_empty() {
            continue;
        }

        let client_id_key = format!("OIDC_{name}_CLIENT_ID");
        let client_id = std::env::var(&client_id_key).unwrap_or_default();
        if client_id.is_empty() {
            return Err(format!("{client_id_key} is required when {key} is set"));
        }

        let email_claim_key = format!("OIDC_{name}_EMAIL_CLAIM");
        let email_claim = std::env::var(&email_claim_key).unwrap_or_else(|_| "email".to_string());

        providers.push(OidcProviderConfig {
            name: name.to_lowercase(),
            discovery_url,
            client_id,
            email_claim,
        });
    }

    if providers.is_empty() && *environment != Environment::Local {
        return Err(
            "at least one OIDC provider (OIDC_*_DISCOVERY_URL) is required in non-local environments"
                .to_string(),
        );
    }

    if providers.is_empty() {
        tracing::warn!(
            "no OIDC providers configured; /auth/token will reject every id_token — \
             for local stacks, deploy the br-oidc-test-idp fixture and declare it as a provider"
        );
    }

    Ok(providers)
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_u16_env(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    parse_bool_value(std::env::var(name).ok().as_deref(), default)
}

/// Parse a bool from an optional string. Pure, side-effect-free (testable).
fn parse_bool_value(value: Option<&str>, default: bool) -> bool {
    value.map(|v| v == "true" || v == "1").unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_defaults_to_true_when_unset() {
        assert!(parse_bool_value(None, true));
    }

    #[test]
    fn parse_bool_defaults_to_false_when_unset() {
        assert!(!parse_bool_value(None, false));
    }

    #[test]
    fn parse_bool_accepts_true_literal() {
        assert!(parse_bool_value(Some("true"), false));
    }

    #[test]
    fn parse_bool_accepts_one() {
        assert!(parse_bool_value(Some("1"), false));
    }

    #[test]
    fn parse_bool_rejects_false_literal() {
        assert!(!parse_bool_value(Some("false"), true));
    }

    #[test]
    fn parse_bool_rejects_zero() {
        assert!(!parse_bool_value(Some("0"), true));
    }

    #[test]
    fn parse_bool_rejects_empty_string() {
        // Empty string is present-but-empty; not "true" or "1" → falls through
        // to the map() comparison returning false (which the current rule does).
        assert!(!parse_bool_value(Some(""), true));
    }
}
