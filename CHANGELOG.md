# Changelog

All notable changes to `svc-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
