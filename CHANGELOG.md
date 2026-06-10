# Changelog

All notable changes to `svc-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## 0.3.0

### Removed

- **BREAKING / Security**: `ALLOW_INSECURE` is gone — the config key, the unverified-claims fallback in `/auth/token`, and `parse_insecure_claims()`. The shipped binary has no code path that skips OIDC verification: an id_token that does not verify against a configured provider is rejected, in every environment. The Helm chart's `allowInsecure` value is removed as well. Closes the platform epic "Eliminate the ALLOW_UNSECURE auth bypass" (ws-cc-platform#1 / #3)

### Added

- E2E coverage of the OIDC verification path (ws-cc-platform#6), against the pilotable test IdPs from [br-e2e-harness](https://github.com/BotResources/br-e2e-harness): full `/auth/token` flow (valid id_token → access + refresh cookies → `/auth/check` → `/auth/refresh` rotation), JWKS refresh on unknown `kid` after an IdP key rotation, rejection of tokens signed with keys absent from the JWKS, cooldown semantics proven via the fixture's fetch counters (suppressed re-fetch inside the window, re-fetch after expiry), multi-provider routing by issuer (including an Entra-shaped `preferred_username` claim), audience mismatch and expired-token rejection
- `JWKS_REFRESH_COOLDOWN_SECONDS` (default `60`): the per-provider JWKS re-fetch cooldown is now configurable; e2e stacks lower it instead of stalling

### Migration

- Deployments that set `ALLOW_INSECURE=true` (local/e2e stacks) must instead run a real test IdP and declare it via `OIDC_*_DISCOVERY_URL` / `OIDC_*_CLIENT_ID` — see `.env.example` and `docker-compose.e2e.yml`

## 0.2.2

### Fixed

- **OIDC JWKS refresh**: JWKS keys are now cached per-provider and refreshed automatically when an id_token arrives with an unknown `kid`. Previously keys were fetched once at startup and never refreshed, causing all logins to fail silently after a provider key rotation. Cooldown of 60s per provider prevents re-fetch storms from invalid tokens. Resolves [#18](https://github.com/BotResources/svc-auth/issues/18)

### Changed

- Replaced `openidconnect` crate with direct OIDC discovery via `reqwest` + signature verification via `jsonwebtoken`. Reduces dependency tree and gives full control over JWKS caching

## 0.2.1

### Fixed

- **`/auth/check`**: expired JWT cookie now correctly returns **401** when `AUTH_CHECK_SILENT_REFRESH=false`. Root cause: `jsonwebtoken` default leeway of 60s was silently accepting tokens expired by less than 60 seconds. Leeway reduced to 5s for both access and refresh token verification. Resolves [#13](https://github.com/BotResources/svc-auth/issues/13)
- **`/auth/refresh`**: 401 responses now include `Set-Cookie` headers clearing both `access_token` and `refresh_token` cookies (`Max-Age=0`). Previously the browser kept stale HttpOnly cookies, trapping SPA clients in a 401 loop with no recovery path. Resolves [#5](https://github.com/BotResources/svc-auth/issues/5)

### Added

- E2E test harness (`tests/e2e.rs`) with Docker Compose (real NATS, native svc-auth binary, no mocks). CI job `e2e` gates merge to main

## 0.2.0

### Changed

- **Breaking:** `/auth/check` now rejects invalid bearer tokens with **401 Unauthorized** instead of silently accepting them as anonymous. Valid tokens and requests with no `Authorization` header are unchanged (200 OK). NATS KV lookup failures return **502 Bad Gateway** instead of failing open to anonymous
- `BearerValidator::is_valid()` returns `Result<bool>` instead of `bool` to let callers distinguish "token not found" from "infrastructure error"

## 0.1.2

### Changed

- Bearer-token KV-key derivation now comes from `br-core-auth` v0.5.0 (`bearer_token_key`), the canonical cross-service contract for the `bearer_tokens` NATS KV bucket. The local `hash_bearer` / `hex_encode` helpers in `bearer_validator.rs` are removed. Hash format is unchanged (lowercase-hex SHA-256), existing KV entries stay resolvable — no migration needed. Resolves [#8](https://github.com/BotResources/svc-auth/issues/8)

## 0.1.1

### Added

- `AUTH_CHECK_SILENT_REFRESH` env var (default `true`, backward compatible). When `false`, `/auth/check` returns **401** on expired or invalid JWT instead of rotating tokens + `Set-Cookie`. Required behind k8s ingress middlewares that cannot forward `Set-Cookie` from auth responses (Traefik ForwardAuth, nginx-ingress `auth-url`, Envoy ExternalAuthz). In that mode the client is expected to catch 401 and call `/auth/refresh` explicitly (standard SPA pattern). Resolves [#1](https://github.com/BotResources/svc-auth/issues/1)
- `authCheck.silentRefresh` value in the Helm chart, wired to the env var. Chart `values-local.yaml` now sets it to `false` for K3d/Traefik

## 0.1.0

### Added

- Helm chart at `charts/br-svc-auth/` (minimal: Deployment, Service, ServiceAccount). Published to `oci://ghcr.io/botresources/charts/br-svc-auth` alongside the image in the CD pipeline. Chart version tracks `Cargo.toml` in lockstep
- `values-local.yaml` example for K3d / K3s local testing
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
