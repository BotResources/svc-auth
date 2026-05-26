//! svc-auth composition root.
//!
//! Portable, self-contained authentication gatekeeper. REST only.
//! Zero workspace dependencies. Multi-provider OIDC with kid-based JWKS refresh.
//! Uses NATS KV for refresh token storage (no PostgreSQL).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderName, Method};
use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

use svc_auth::AppState;
use svc_auth::bearer_validator::BearerValidator;
use svc_auth::config::AppConfig;
use svc_auth::cookie::CookieConfig;
use svc_auth::jwt::JwtService;
use svc_auth::oidc_validator::OidcValidator;
use svc_auth::refresh_store::RefreshTokenStore;

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("svc-auth {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

    // -- NATS --
    let nats_client = match async_nats::connect(&config.nats_url).await {
        Ok(c) => {
            tracing::info!("NATS connected");
            c
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to NATS");
            std::process::exit(1);
        }
    };

    let jetstream = async_nats::jetstream::new(nats_client);

    // -- NATS KV: bearer_tokens (read-only, created if absent) --
    let bearer_validator = match jetstream
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: "bearer_tokens".to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(kv) => {
            tracing::info!("NATS KV bearer_tokens connected");
            Some(Arc::new(BearerValidator::new(kv)))
        }
        Err(e) => {
            tracing::warn!(error = %e, "NATS KV bearer_tokens unavailable; bearer validation will fail-open to anonymous");
            None
        }
    };

    // -- NATS KV: refresh token storage --
    let refresh_ttl = std::time::Duration::from_secs(config.refresh_token_ttl);

    let refresh_tokens_kv = jetstream
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: "auth_refresh_tokens".to_string(),
            max_age: refresh_ttl,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to create auth_refresh_tokens KV bucket");
            std::process::exit(1);
        });

    let revoked_families_kv = jetstream
        .create_key_value(async_nats::jetstream::kv::Config {
            bucket: "auth_revoked_families".to_string(),
            max_age: refresh_ttl,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to create auth_revoked_families KV bucket");
            std::process::exit(1);
        });

    tracing::info!("NATS KV buckets initialized (refresh_tokens, revoked_families)");

    // -- JWT service --
    let jwt = Arc::new(JwtService::new(
        &config.jwt_secret,
        &config.jwt_issuer,
        config.access_token_ttl,
        config.refresh_token_ttl,
    ));

    // -- OIDC providers (auto-discovered from env vars) --
    let oidc = if config.oidc_providers.is_empty() {
        tracing::warn!("no OIDC providers configured");
        Arc::new(OidcValidator::empty())
    } else {
        match OidcValidator::discover(&config.oidc_providers).await {
            Ok(v) => Arc::new(v),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize OIDC providers");
                std::process::exit(1);
            }
        }
    };

    // -- Cookie config --
    let cookie_config = CookieConfig::new(
        config.secure_cookies,
        config.refresh_token_ttl,
        config.access_token_ttl,
    );

    // -- Refresh token store (NATS KV) --
    let refresh_store = Arc::new(RefreshTokenStore::new(
        refresh_tokens_kv,
        revoked_families_kv,
    ));

    let state = AppState {
        jwt,
        oidc,
        refresh_store,
        bearer_validator,
        cookie_config,
        allow_insecure: config.allow_insecure,
        auth_check_silent_refresh: config.auth_check_silent_refresh,
    };

    if !state.auth_check_silent_refresh {
        tracing::info!(
            "AUTH_CHECK_SILENT_REFRESH=false — /auth/check returns 401 on expired JWT; \
             clients must call /auth/refresh explicitly"
        );
    }

    // -- CORS --
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "http://localhost:5173".parse().unwrap(),
            "http://localhost:3000".parse().unwrap(),
        ]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
        ])
        .allow_credentials(true);

    // -- Router --
    let app = Router::new()
        .route("/auth/check", get(svc_auth::auth_check::auth_check_handler))
        .route("/auth/token", post(svc_auth::token::token_handler))
        .route("/auth/refresh", post(svc_auth::refresh::refresh_handler))
        .route("/auth/logout", post(svc_auth::logout::logout_handler))
        .route("/health", get(svc_auth::health::health_handler))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("svc-auth listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
