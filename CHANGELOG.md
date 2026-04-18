# Changelog

All notable changes to `svc-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## 0.1.0

### Added

- Portable, self-contained REST authentication gatekeeper
- Multi-provider OIDC id_token verification (auto-discovered from `OIDC_*_DISCOVERY_URL` env vars)
- Internal JWT signing with `sub = email` (HMAC-SHA256, 15 min default TTL)
- Refresh token rotation with family-based reuse detection
- Refresh token storage in NATS KV (`auth_refresh_tokens` + `auth_revoked_families` buckets, TTL-aligned)
- Compare-and-swap on refresh token updates (atomic revision-based)
- Silent refresh via `GET /auth/check` (nginx `auth_request` pattern)
- Bearer token validation via NATS KV (`bearer_tokens`, SHA-256 hash lookup, read-only)
- HttpOnly cookie management (`__Host-` prefix in production)
- `GET /health` endpoint reporting NATS KV bucket reachability
- Zero database dependencies — pure NATS KV storage
