# Changelog

All notable changes to `svc-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed

- **BREAKING (behaviour, not wire): the session cookie now has a lifecycle.**
  `__Host-session_id` used to be written once per *browser jar* and never removed —
  `/auth/token` minted one only when absent, `logout` cleared access and refresh but
  not it, and the cookie carried neither `Max-Age` nor `Expires`. A logout → login
  round trip in the same window therefore kept the previous session's correlation id.
  Now: `/auth/token` writes a **new** id on every successful exchange, and `logout`
  clears it alongside the other two. `/auth/refresh` and `/auth/check` are unchanged
  and still write one only when absent — a rotation is the same sign-in continuing,
  and that property is now pinned by a test.
- **New:** `cookie::build_clear_session_cookie` — the twin of the existing
  `build_clear_access_cookie` / `build_clear_refresh_cookie`, mirroring the exact
  attributes `build_session_cookie` sets (`HttpOnly; Secure; SameSite=Lax; Path=/`)
  plus `Max-Age=0`, so the browser matches and drops the cookie.
- **A failed `/auth/token` no longer opens a session.** The id was previously minted
  on the success path only when absent; it is now minted on the success path only,
  full stop.
- `token_handler` no longer takes `HeaderMap` — it has nothing left to read from the
  request.

Two consumers of this behaviour, both stated so the change can be judged:
a correlation id surviving a sign-out on a shared machine is a privacy defect in its
own right, and `bma-identity` 0.1.3 binds a borrowed identity (impersonation) to this
id — so the old lifecycle meant a borrowed identity outliving a logout. Downstream
services that treated the id as *stable for the life of the browser* will see it
change on every sign-in; that is the point, but it is a behaviour change.

### Tests

- `logout_clears_the_session_cookie_with_the_other_two` replaces
  `logout_does_not_clear_session_cookie`, which pinned the old behaviour.
- `logging_out_and_back_in_does_not_reuse_the_previous_session_id`,
  `two_sign_ins_on_the_same_jar_get_two_session_ids`,
  `a_failed_exchange_opens_no_session`.
- `a_silent_refresh_leaves_the_session_id_alone` — the property downstream depends
  on, previously untested and easy to break while changing the above.

## 1.0.4

### Changed

- Dependency-only patch: `br-rust-common` pins v1.1.0 → **v1.2.0** (picks up the
  NoResponders-recoverable consumer recovery and the supervised
  `PublishedLanguageConsumer::run()`; `WatchHealth` now starts `Degraded` and is
  written only by the supervised loop) and `br-test-harness` v1.1.0 → **v1.1.2**.
  No svc-auth surface change. Part of the v1.2.0 consumer wave unblocking
  be-botresources#242.

## 1.0.3

### Changed

- **Bumped `br-rust-common` to v1.1.0 and `br-e2e-harness` (`br-test-harness`)
  to v1.1.0** across every crate (`br-core-auth`, `br-core-kernel`,
  `br-util-nats-fabric`, `br-util-observability`, `br-util-axum-readiness`, and
  the test harness). Mechanical pin refresh — both the `tag` and the `version`
  requirement move together on each git dependency. The service wire (HTTP
  endpoints, NATS subjects, the sealed-bearer contract) is unchanged, so this is
  a patch.
- The v1.1.0 fabric run-loop now **auto-recovers from transient missed
  JetStream heartbeats** instead of surfacing them as a fatal consume error, so
  the bearer reader and refresh store ride out a brief broker hiccup without a
  restart. This is an inherited resilience benefit — no svc-auth code change
  (the new `ConsumeErrorKind::HeartbeatMissed` variant is handled inside the
  fabric; svc-auth never matches on it).
- Refreshed lockfile-only advisory bumps: `crossbeam-epoch` 0.9.18 -> 0.9.20
  (RUSTSEC-2026-0204) and `quinn-proto` 0.11.14 -> 0.11.16 (RUSTSEC-2026-0185,
  an optional reqwest `http3` transitive not compiled in this build).

## 1.0.2

### Security

- **Refresh-token reuse detection is now symmetric across both rotation paths.**
  `/auth/check`'s silent refresh (`AUTH_CHECK_SILENT_REFRESH=true`) previously
  swallowed a CAS conflict on `mark_used` and cleared cookies **without revoking
  the family**, leaving a reused family active with two live tokens — asymmetric
  with `/auth/refresh`. Both handlers now route rotation through a single
  `rotation::rotate` primitive: reuse — a `used_at` replay **or** a concurrent
  CAS conflict — revokes the whole token family in exactly one place. A
  non-CAS error from `mark_used` fails the rotation closed on both paths (no
  cookies handed out; the old token stays replayable for a safe retry).

### Changed

- **The two ad-hoc refresh KV buckets are collapsed into the single fabric
  `EPHEMERAL_AUTH` bucket.** `auth_refresh_tokens` and `auth_revoked_families`
  no longer exist; refresh tokens are stored under the `refresh.` key prefix and
  revoked families under the `revoked.` key prefix in the one `EPHEMERAL_AUTH`
  bucket. This brings svc-auth onto the two sanctioned fabric KV buckets
  (`EPHEMERAL_AUTH`, `PUBLISHED_LANGUAGE`) and away from caller-named buckets.
- **All direct `async_nats` usage is removed** — every NATS access (refresh
  store and bearer reader) now goes through `br-util-nats-fabric`. The boot no
  longer opens its own `async_nats` connection / JetStream context; the single
  `Fabric` connection serves both the bearer reader and the refresh store.
- **Refresh-token rotation is now compare-and-swap through the fabric.**
  `mark_used` reads the current revision (`get_with_revision`) and rotates with
  `update_if`; a lost CAS race surfaces as a precise reuse verdict
  (`401 token_reuse_detected`, family revoked), never a last-write-wins
  overwrite.
- The `EPHEMERAL_AUTH` bucket replaces `auth_refresh_tokens` /
  `auth_revoked_families` in the boot bind-list; an absent `EPHEMERAL_AUTH` fails
  the boot (bind-only, fail-loud — never auto-created).
- **The e2e suite is now free of direct `async_nats`.** Tests provision NATS KV
  through the harness `FabricTestNats` (`with_published_language()` +
  `with_ephemeral_auth()`) and assert the exact live bucket inventory via
  `assert_only_kv_buckets`; `async-nats` is dropped from `[dev-dependencies]`.

## 1.0.1

### Security

- **`/auth/check` now fails closed on an unresolved bearer.** A presented
  `Authorization: Bearer <token>` that does not resolve to a sealed entry in
  `PUBLISHED_LANGUAGE` (key absent, wrong key, or tampered ciphertext) is now
  rejected with **`401`**. Previously an unresolved bearer was treated as an
  anonymous `200` — a fail-open the gateway could mistake for a valid session.
- The binary no longer reads the legacy **plaintext** `br_core_auth::BearerTokenEntry`
  from the standalone `bearer_tokens` bucket. It now reads the **AEAD-sealed**
  `br-auth-contract` wire (`SealedBearer`, ChaCha20-Poly1305, bound to its KV key
  via the AEAD AAD) from the `PUBLISHED_LANGUAGE` bucket under the
  `identity/bearer_tokens/` key prefix — bringing the binary into compliance with
  the already-published bearer contract.

### Changed

- All bearer-path NATS access now goes through the `br-util-nats-fabric` Fabric
  (`PublishedLanguageReader`); the raw `async_nats` bearer lookup is removed. The
  refresh/revoked-family stores are unchanged.
- **New required env `BEARER_SEAL_KEY`** — the base64 (std) ChaCha20-Poly1305
  32-byte seal key used to open sealed bearer entries. Boot fails loud if it is
  absent or not a valid 32-byte key.
- **New required declared bucket `PUBLISHED_LANGUAGE`** replaces `bearer_tokens`
  in the boot bind-list; an absent `PUBLISHED_LANGUAGE` fails the boot (the
  `bearer_tokens` bucket is no longer bound).
- On a resolved bearer, `/auth/check` exposes the resolved actor to the gateway
  via response headers: `X-Auth-User-Id` (for a human actor) or
  `X-Auth-Service-Account-Id` (for a service actor), plus `X-Auth-Token-Id`.
  svc-auth still does **not** build a Passport — it exposes the resolved actor only.

## 1.0.0

### Changed

- Migrated to `br-rust-common` v1.0.2 (`br-core-auth`, `br-util-observability`,
  `br-util-axum-readiness`) and `br-test-harness` v1.0.1. Mechanical pin refresh
  against the unified workspace tags; no public-surface or contract change in the
  consumed crates, and **no behavior change in svc-auth itself**.

### Added

- The **bearer credential contract family**, shipped as workspace-member crates
  (each versioned independently at `0.1.0`):
  - `br-auth-contract` — the **frozen, AEAD-sealed bearer wire**:
    `BearerEntry` / `SealedBearer`, destined for the `PUBLISHED_LANGUAGE` KV
    under the `identity/bearer_tokens/` key prefix. The entry is sealed with
    ChaCha20-Poly1305, **bound to its KV key via the AEAD AAD** so a value
    cannot be lifted to another key.
  - `br-auth-conformance-test` — an **independent-anchor conformance battery**:
    a Go reimplementation freezes the wire, and the test deserializes the
    Go-frozen bytes **through the real `br-auth-contract` types as the oracle**,
    so any drift in the lib's view of the wire fails the test.
  - `br-auth-identity-util` — the **producer kit**: `put` / `delete` of bearer
    entries over the NATS Fabric.

  These crates are **not yet wired into the svc-auth binary** — they are the
  contract + producer + conformance socle for the bearer integration to come.

## 0.5.0

### Security

- **svc-auth gates, it does not block.** On `/auth/check`, an unknown,
  unresolvable, or shape-malformed PAT/bearer credential resolves to **anonymous
  (`200`)**, never `401` — gating a credential is "no session", not "rejected".
  A backend KV error on the lookup returns `502` (the infrastructure is down, the
  request cannot be answered). The JWT-cookie path is unchanged: an expired or
  invalid access-token cookie still returns `401` when
  `AUTH_CHECK_SILENT_REFRESH=false` (the front's explicit-refresh trigger).
- **`bearer_tokens` is a required declared bucket — fail-loud at boot.**
  `bearer_tokens`, `auth_refresh_tokens` and `auth_revoked_families` are *bound*
  (`get_key_value`), never created (`create_key_value`). If any of the three is
  absent at boot, svc-auth **exits non-zero** (`exit(1)`) so Kubernetes
  reschedules it — there is no degraded "up-but-503" mode. Buckets are declared
  by the deployment/tests, not by svc-auth.
- **Bearer KV value is shape-validated.** A present-but-malformed entry (does not
  deserialize into `br_core_auth::BearerTokenEntry`, which is
  `deny_unknown_fields`) is treated as unresolved — it resolves anonymous, not
  valid-by-key-presence.

### Changed

- Bump `br-rust-common` to v0.11.0 (`br-core-auth`, `br-util-observability`,
  `br-util-axum-readiness`).

### Removed

- Dead `RefreshToken.token_hash` field and the direct `sha2` dependency it
  forced. Refresh validation rests on the JWT signature plus the KV
  `find_by_id(jti)` lookup; the stored hash was never read.

## 0.4.1

### Changed

- Relicensed from MIT to Apache-2.0.
- Bump `br-rust-common` to v0.10.0 (`br-core-auth`, `br-util-observability`,
  `br-util-axum-readiness`). Mechanical pin refresh against the unified
  workspace tag; no public-surface or contract change in the consumed crates.

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
