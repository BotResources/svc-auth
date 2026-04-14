//! Cookie helpers for access and refresh tokens.
//!
//! Both cookies share the same security attributes (HttpOnly, SameSite=Strict,
//! Path=/) but differ in name and Max-Age. In production mode, cookies use the
//! `__Host-` prefix and `Secure` flag.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub secure: bool,
    /// Max-Age for the refresh token cookie (seconds).
    pub refresh_max_age: u64,
    /// Max-Age for the access token cookie (seconds).
    pub access_max_age: u64,
}

impl CookieConfig {
    pub fn new(secure: bool, refresh_ttl_secs: u64, access_ttl_secs: u64) -> Self {
        Self {
            secure,
            refresh_max_age: refresh_ttl_secs,
            access_max_age: access_ttl_secs,
        }
    }

    pub fn refresh_cookie_name(&self) -> &str {
        if self.secure {
            "__Host-refresh_token"
        } else {
            "refresh_token"
        }
    }

    pub fn access_cookie_name(&self) -> &str {
        if self.secure {
            "__Host-access_token"
        } else {
            "access_token"
        }
    }
}

// -- Access token cookie --

pub fn build_access_cookie(token: &str, config: &CookieConfig) -> String {
    build_cookie(
        config.access_cookie_name(),
        token,
        config.access_max_age,
        config.secure,
    )
}

pub fn build_clear_access_cookie(config: &CookieConfig) -> String {
    build_cookie(config.access_cookie_name(), "", 0, config.secure)
}

pub fn extract_access_cookie(headers: &HeaderMap, config: &CookieConfig) -> Option<String> {
    extract_cookie(headers, config.access_cookie_name())
}

// -- Refresh token cookie --

pub fn build_refresh_cookie(token: &str, config: &CookieConfig) -> String {
    build_cookie(
        config.refresh_cookie_name(),
        token,
        config.refresh_max_age,
        config.secure,
    )
}

pub fn build_clear_refresh_cookie(config: &CookieConfig) -> String {
    build_cookie(config.refresh_cookie_name(), "", 0, config.secure)
}

pub fn extract_refresh_cookie(headers: &HeaderMap, config: &CookieConfig) -> Option<String> {
    extract_cookie(headers, config.refresh_cookie_name())
}

// -- Internal helpers --

fn build_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    if secure {
        format!("{name}={value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}")
    } else {
        format!("{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}")
    }
}

fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    let prefix = format!("{cookie_name}=");
    cookie_header.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix(&prefix).map(|v| v.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn insecure_config() -> CookieConfig {
        CookieConfig::new(false, 604_800, 900)
    }

    fn secure_config() -> CookieConfig {
        CookieConfig::new(true, 604_800, 900)
    }

    #[test]
    fn insecure_access_cookie_name() {
        assert_eq!(insecure_config().access_cookie_name(), "access_token");
    }

    #[test]
    fn secure_access_cookie_name() {
        assert_eq!(secure_config().access_cookie_name(), "__Host-access_token");
    }

    #[test]
    fn insecure_refresh_cookie_name() {
        assert_eq!(insecure_config().refresh_cookie_name(), "refresh_token");
    }

    #[test]
    fn secure_refresh_cookie_name() {
        assert_eq!(
            secure_config().refresh_cookie_name(),
            "__Host-refresh_token"
        );
    }

    #[test]
    fn build_access_cookie_insecure() {
        let c = build_access_cookie("jwt", &insecure_config());
        assert_eq!(
            c,
            "access_token=jwt; HttpOnly; SameSite=Strict; Path=/; Max-Age=900"
        );
    }

    #[test]
    fn build_access_cookie_secure() {
        let c = build_access_cookie("jwt", &secure_config());
        assert!(c.starts_with("__Host-access_token=jwt;"));
        assert!(c.contains("Secure"));
        assert!(c.contains("Max-Age=900"));
    }

    #[test]
    fn build_refresh_cookie_insecure() {
        let c = build_refresh_cookie("tok", &insecure_config());
        assert_eq!(
            c,
            "refresh_token=tok; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800"
        );
    }

    #[test]
    fn build_refresh_cookie_secure() {
        let c = build_refresh_cookie("tok", &secure_config());
        assert!(c.starts_with("__Host-refresh_token=tok;"));
        assert!(c.contains("Secure"));
    }

    #[test]
    fn clear_access_cookie_has_zero_max_age() {
        let c = build_clear_access_cookie(&insecure_config());
        assert!(c.contains("Max-Age=0"));
        assert!(c.starts_with("access_token=;"));
    }

    #[test]
    fn clear_refresh_cookie_has_zero_max_age() {
        let c = build_clear_refresh_cookie(&insecure_config());
        assert!(c.contains("Max-Age=0"));
        assert!(c.starts_with("refresh_token=;"));
    }

    #[test]
    fn extract_access_cookie_from_headers() {
        let cfg = insecure_config();
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("access_token=jwt123"));
        assert_eq!(
            extract_access_cookie(&headers, &cfg),
            Some("jwt123".to_string())
        );
    }

    #[test]
    fn extract_refresh_cookie_from_headers() {
        let cfg = insecure_config();
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("refresh_token=rt123"));
        assert_eq!(
            extract_refresh_cookie(&headers, &cfg),
            Some("rt123".to_string())
        );
    }

    #[test]
    fn extract_access_cookie_missing_returns_none() {
        let cfg = insecure_config();
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("refresh_token=rt"));
        assert_eq!(extract_access_cookie(&headers, &cfg), None);
    }

    #[test]
    fn extract_from_multiple_cookies() {
        let cfg = insecure_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("access_token=jwt; refresh_token=rt"),
        );
        assert_eq!(
            extract_access_cookie(&headers, &cfg),
            Some("jwt".to_string())
        );
        assert_eq!(
            extract_refresh_cookie(&headers, &cfg),
            Some("rt".to_string())
        );
    }
}
