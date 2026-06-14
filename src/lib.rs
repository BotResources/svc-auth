pub mod auth_check;
pub mod bearer_validator;
pub mod config;
pub mod cookie;
pub mod error;
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

#[derive(Clone)]
pub struct AppState {
    pub jwt: Arc<JwtService>,
    pub oidc: Arc<OidcValidator>,
    pub refresh_store: Arc<RefreshTokenStore>,
    pub bearer_validator: Arc<BearerValidator>,
    pub cookie_config: CookieConfig,
    pub auth_check_silent_refresh: bool,
}
