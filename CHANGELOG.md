# Changelog

All notable changes to `svc-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed

- Relicensed from MIT to Apache-2.0.

## 0.4.0

### Changed

- **Probe surface (BREAKING for deployments):** the single `GET /health`
  endpoint is replaced by the platform's three-probe split, adopted from
  `br-rust-common`:
  - `GET /livez` — liveness, **always 200** (`br-util-observability`). Kubernetes
    restarts the pod only when the process is dead, never on a transient NATS
    outage. The Helm chart's `livenessProbe` switches from `tcpSocket` to an
    `httpGet` on `/livez`.
  - `GET /readyz` — readiness (`br-util-axum-readiness`). 200 once the NATS KV
    buckets are confirmed reachable at startup, 503 otherwise; the pod is taken
    out of rotation rather than restarted. The chart's `readinessProbe` path
    moves from `/health` to `/readyz`.
  - `GET /metrics` — anonymized Prometheus exposition (`br-util-observability`),
    with an HTTP metrics layer labeling by method + matched-route template +
    status (no PII, no raw path).

  Any deployment that probed `/health` must move to `/livez` (liveness) and
  `/readyz` (readiness).
- **Structured JSON logging** now comes from `br-util-observability`'s
  `init_logging("svc-auth")` (one JSON object per line, canonical `ts`/`level`/
  `component`/`msg` keys), replacing the hand-rolled `tracing_subscriber::fmt`.
  Level remains env-driven (`RUST_LOG`, default `info`); the local
  `tracing-subscriber` dependency is dropped.

### Added

- Dependencies on `br-util-observability` and `br-util-axum-readiness`, both
  pinned to the unified `br-rust-common` tag `v0.8.0`.

### Security

- The `v0.8.0` dependency refresh clears both previously-ignored advisories:
  `rsa` (RUSTSEC-2023-0071) is no longer in the tree, and `rustls-webpki`
  resolves to a patched `0.103`, out of RUSTSEC-2026-0049's range. The
  `deny.toml` ignore list is now empty — a vulnerable reappearance fails CI
  instead of being silently allowed.

### Migration

- `br-core-auth` is re-pinned from the per-crate tag `br-core-auth-v0.6.0` to
  the unified workspace tag `v0.8.0`; the bearer/session contract is unchanged.
- Operators must update probe paths: liveness → `/livez`, readiness → `/readyz`.
  The bundled Helm chart is already updated; external deploy manifests that
  hardcode `/health` must follow.

## 0.3.1

### Changed

- **Security: `ENVIRONMENT` parsing now fails closed.** Previously an
  unrecognised `ENVIRONMENT` value silently fell back to `Environment::Local`
  (`_ => Environment::Local`). For an auth service, defaulting an unknown
  environment to the most-permissive mode is the wrong direction — a typo'd
  or newly-introduced environment now fails loud at boot instead. Concretely,
  `ENVIRONMENT=uat` / `ENVIRONMENT=stg` were being treated as `Local`, which
  bypassed the "non-local requires a configured OIDC provider" guard.

### Added

- `uat` and `stg` (Staging) are now recognised `ENVIRONMENT` values, parsed
  by a new pure `Environment::parse` helper with unit coverage (known values
  accepted, unknown/wrong-case rejected).

## 0.3.0

### Removed

- **BREAKING / Security**: `ALLOW_INSECURE` is gone — the config key, the unverified-claims fallback in `/auth/token`, and `parse_insecure_claims()`. The shipped binary has no code path that skips OIDC verification: an id_token that does not verify against a configured provider is rejected, in every environment. The Helm chart's `allowInsecure` value is removed as well.

### Added

- E2E coverage of the OIDC verification path, against the pilotable test IdPs from [br-e2e-harness](https://github.com/BotResources/br-e2e-harness): full `/auth/token` flow (valid id_token → access + refresh cookies → `/auth/check` → `/auth/refresh` rotation), JWKS refresh on unknown `kid` after an IdP key rotation, rejection of tokens signed with keys absent from the JWKS, cooldown semantics proven via the fixture's fetch counters (suppressed re-fetch inside the window, re-fetch after expiry), multi-provider routing by issuer (including an Entra-shaped `preferred_username` claim), audience mismatch and expired-token rejection
- `JWKS_REFRESH_COOLDOWN_SECONDS` (default `60`): the per-provider JWKS re-fetch cooldown is now configurable; e2e stacks lower it instead of stalling

### Migration

- Deployments that set `ALLOW_INSECURE=true` (local/e2e stacks) must instead run a real test IdP and declare it via `OIDC_*_DISCOVERY_URL` / `OIDC_*_CLIENT_ID` — see `.env.example` and `docker-compose.e2e.yml`

## 0.2.2

### Fixed

- **OIDC JWKS refresh**: JWKS keys are now cached per-provider and refreshed automatically when an id_token arrives with an unknown `kid`. Previously keys were fetched once at startup and never refreshed, causing all logins to fail silently after a provider key rotation. Cooldown of 60s per provider prevents re-fetch storms from invalid tokens. Resolves #18

### Changed

- Replaced `openidconnect` crate with direct OIDC discovery via `reqwest` + signature verification via `jsonwebtoken`. Reduces dependency tree and gives full control over JWKS caching

## 0.2.1

### Fixed

- **`/auth/check`**: expired JWT cookie now correctly returns **401** when `AUTH_CHECK_SILENT_REFRESH=false`. Root cause: `jsonwebtoken` default leeway of 60s was silently accepting tokens expired by less than 60 seconds. Leeway reduced to 5s for both access and refresh token verification. Resolves #13
- **`/auth/refresh`**: 401 responses now include `Set-Cookie` headers clearing both `access_token` and `refresh_token` cookies (`Max-Age=0`). Previously the browser kept stale HttpOnly cookies, trapping SPA clients in a 401 loop with no recovery path. Resolves #5

### Added

- E2E test harness (`tests/e2e.rs`) with Docker Compose (real NATS, native svc-auth binary, no mocks). CI job `e2e` gates merge to main

## 0.2.0

### Changed

- **Breaking:** `/auth/check` now rejects invalid bearer tokens with **401 Unauthorized** instead of silently accepting them as anonymous. Valid tokens and requests with no `Authorization` header are unchanged (200 OK). NATS KV lookup failures return **502 Bad Gateway** instead of failing open to anonymous
- `BearerValidator::is_valid()` returns `Result<bool>` instead of `bool` to let callers distinguish "token not found" from "infrastructure error"

## 0.1.2

### Changed

- Bearer-token KV-key derivation now comes from `br-core-auth` v0.5.0 (`bearer_token_key`), the canonical cross-service contract for the `bearer_tokens` NATS KV bucket. The local `hash_bearer` / `hex_encode` helpers in `bearer_validator.rs` are removed. Hash format is unchanged (lowercase-hex SHA-256), existing KV entries stay resolvable — no migration needed. Resolves #8

## 0.1.1

### Added

- `AUTH_CHECK_SILENT_REFRESH` env var (default `true`, backward compatible). When `false`, `/auth/check` returns **401** on expired or invalid JWT instead of rotating tokens + `Set-Cookie`. Required behind k8s ingress middlewares that cannot forward `Set-Cookie` from auth responses (Traefik ForwardAuth, nginx-ingress `auth-url`, Envoy ExternalAuthz). In that mode the client is expected to catch 401 and call `/auth/refresh` explicitly (standard SPA pattern). Resolves #1
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
