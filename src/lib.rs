//! svc-auth -- portable, self-contained authentication gatekeeper.
//!
//! Zero workspace dependencies. REST only. No GraphQL, no event sourcing,
//! no Passport knowledge. Proves identity ("the human behind this request
//! controls this email") and validates bearer tokens.
//!
//! Supports multiple OIDC providers simultaneously. Providers are auto-detected
//! from OIDC_*_DISCOVERY_URL environment variables at startup.

pub mod auth_check;
pub mod bearer_validator;
pub mod config;
pub mod cookie;
pub mod error;
pub mod health;
pub mod jwt;
pub mod logout;
pub mod oidc_validator;
pub mod refresh;
pub mod refresh_store;
pub mod token;

use std::sync::Arc;

use crate::bearer_validator::BearerValidator;
use crate::cookie::CookieConfig;
use crate::jwt::JwtService;
use crate::oidc_validator::OidcValidator;
use crate::refresh_store::RefreshTokenStore;

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub jwt: Arc<JwtService>,
    pub oidc: Arc<OidcValidator>,
    pub refresh_store: Arc<RefreshTokenStore>,
    pub bearer_validator: Option<Arc<BearerValidator>>,
    pub cookie_config: CookieConfig,
    /// When false, `/auth/check` does not rotate refresh tokens on expired
    /// JWT — it returns 401 instead. Clients must call `/auth/refresh`
    /// explicitly. Set this for k8s ingress middlewares that cannot forward
    /// Set-Cookie from auth responses (Traefik ForwardAuth, nginx-ingress
    /// auth-url, Envoy ExternalAuthz).
    pub auth_check_silent_refresh: bool,
}
