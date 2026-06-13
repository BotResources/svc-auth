use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderName, Method};
use axum::routing::{get, post};
use br_util_axum_readiness::{ReadinessHandle, readiness_route};
use br_util_observability::{
    http_metrics_layer, init_logging, init_metrics, liveness_route, metrics_route,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

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

    init_logging("svc-auth");

    let metrics = match init_metrics("svc-auth") {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to install metrics recorder");
            std::process::exit(1);
        }
    };

    let readiness = ReadinessHandle::not_ready("starting up");

    let config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

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

    let jwt = Arc::new(JwtService::new(
        &config.jwt_secret,
        &config.jwt_issuer,
        config.access_token_ttl,
        config.refresh_token_ttl,
    ));

    let oidc = if config.oidc_providers.is_empty() {
        tracing::warn!("no OIDC providers configured — /auth/token will reject every id_token");
        Arc::new(OidcValidator::empty())
    } else {
        let cooldown = std::time::Duration::from_secs(config.jwks_refresh_cooldown_secs);
        match OidcValidator::discover(&config.oidc_providers, cooldown).await {
            Ok(v) => Arc::new(v),
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize OIDC providers");
                std::process::exit(1);
            }
        }
    };

    let cookie_config = CookieConfig::new(
        config.secure_cookies,
        config.refresh_token_ttl,
        config.access_token_ttl,
    );

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
        auth_check_silent_refresh: config.auth_check_silent_refresh,
    };

    if !state.auth_check_silent_refresh {
        tracing::info!(
            "AUTH_CHECK_SILENT_REFRESH=false — /auth/check returns 401 on expired JWT; \
             clients must call /auth/refresh explicitly"
        );
    }

    let refresh_store_ok = state.refresh_store.is_healthy().await;
    let bearer_ok = match state.bearer_validator {
        Some(ref validator) => validator.is_healthy().await,
        None => true,
    };
    if refresh_store_ok && bearer_ok {
        readiness.set_ready();
    } else {
        readiness.set_not_ready("NATS KV buckets unreachable");
    }

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

    let app = Router::new()
        .route("/auth/check", get(svc_auth::auth_check::auth_check_handler))
        .route("/auth/token", post(svc_auth::token::token_handler))
        .route("/auth/refresh", post(svc_auth::refresh::refresh_handler))
        .route("/auth/logout", post(svc_auth::logout::logout_handler))
        .with_state(state)
        .route("/livez", liveness_route())
        .route("/readyz", readiness_route(readiness))
        .route("/metrics", metrics_route(metrics))
        .layer(http_metrics_layer())
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("svc-auth listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
