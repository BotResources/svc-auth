use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use br_auth_contract::BearerSealKey;

const JWKS_REFRESH_COOLDOWN_FLOOR_SECS: u64 = 1;

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
    pub jwks_refresh_cooldown_secs: u64,
    pub bearer_seal_key: BearerSealKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    Local,
    Dev,
    Test,
    Uat,
    Staging,
    Prod,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Dev => write!(f, "dev"),
            Self::Test => write!(f, "test"),
            Self::Uat => write!(f, "uat"),
            Self::Staging => write!(f, "stg"),
            Self::Prod => write!(f, "prod"),
        }
    }
}

impl Environment {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "local" => Ok(Self::Local),
            "dev" => Ok(Self::Dev),
            "test" => Ok(Self::Test),
            "uat" => Ok(Self::Uat),
            "stg" => Ok(Self::Staging),
            "prod" => Ok(Self::Prod),
            other => Err(format!(
                "ENVIRONMENT must be one of local|dev|test|uat|stg|prod, got {other:?}"
            )),
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
    pub fn from_env() -> Result<Self, String> {
        let nats_url = required_env("NATS_URL")?;
        let jwt_secret = required_env("JWT_SECRET")?;

        let jwt_issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "svc-auth".to_string());
        let access_token_ttl = parse_u64_env("JWT_ACCESS_TOKEN_TTL", 900);
        let refresh_token_ttl = parse_u64_env("JWT_REFRESH_TOKEN_TTL", 604_800);
        let port = parse_u16_env("PORT", 8002);

        let environment = Environment::parse(
            std::env::var("ENVIRONMENT")
                .unwrap_or_else(|_| "local".to_string())
                .as_str(),
        )?;

        let secure_cookies = parse_bool_env("SECURE_COOKIES", true);

        let jwks_refresh_cooldown_secs = parse_u64_env("JWKS_REFRESH_COOLDOWN_SECONDS", 60)
            .max(JWKS_REFRESH_COOLDOWN_FLOOR_SECS);

        let auth_check_silent_refresh = parse_bool_env("AUTH_CHECK_SILENT_REFRESH", true);

        let bearer_seal_key = parse_bearer_seal_key()?;

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
            bearer_seal_key,
        })
    }
}

fn parse_bearer_seal_key() -> Result<BearerSealKey, String> {
    let encoded = required_env("BEARER_SEAL_KEY")?;
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "BEARER_SEAL_KEY must be valid base64".to_string())?;
    BearerSealKey::from_bytes(&bytes).map_err(|e| format!("BEARER_SEAL_KEY is invalid: {e}"))
}

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
        assert!(!parse_bool_value(Some(""), true));
    }

    #[test]
    fn environment_parses_all_known_values() {
        for (raw, expected) in [
            ("local", Environment::Local),
            ("dev", Environment::Dev),
            ("test", Environment::Test),
            ("uat", Environment::Uat),
            ("stg", Environment::Staging),
            ("prod", Environment::Prod),
        ] {
            assert_eq!(Environment::parse(raw).unwrap(), expected);
        }
    }

    #[test]
    fn environment_rejects_unknown_value() {
        assert!(Environment::parse("sandbox").is_err());
        assert!(Environment::parse("Prod").is_err());
    }
}
