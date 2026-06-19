# svc-auth

> [!IMPORTANT]
> **This repository is maintained for BotResources and its authorized clients.**
> It is published under Apache-2.0 and made available read-only for visibility and
> reuse. The Apache-2.0 license governs your rights to use, modify, and fork the code;
> the rest of this notice describes our operational stance, not a legal
> restriction.
>
> **We do not accept external pull requests, issues, or support requests.**
> Issues and Discussions are disabled. PRs from accounts that are not on the
> internal contributor allowlist will be closed without review. Forks are
> permitted by Apache-2.0 and we do not (and cannot) prevent them; we simply do not
> monitor, support, or accept contributions from forks outside the BR
> commercial relationship.
>
> - Clients with a commercial relationship: contact your BR account manager.
> - Security reports: see [SECURITY.md](SECURITY.md) (private email channel).
> - This is not a community-supported project. No support is provided through
>   GitHub.

Portable, self-contained REST authentication gatekeeper. Zero infrastructure dependencies beyond NATS (no database).

Proves identity ("the human behind this request controls this email") via multi-provider OIDC, signs internal JWTs, and validates bearer tokens. Does **not** manage users, permissions, or sessions -- that's the consuming project's responsibility.

## Endpoints

| Method | Path             | Description                                      |
|--------|------------------|--------------------------------------------------|
| POST   | `/auth/token`    | Exchange OIDC id_token for internal JWT (cookies) |
| POST   | `/auth/refresh`  | Rotate refresh token, get new access token        |
| GET    | `/auth/check`    | nginx `auth_request` -- validate JWT cookie, or resolve a sealed bearer (`401` if unresolved) |
| POST   | `/auth/logout`   | Revoke refresh token family, clear cookies        |
| GET    | `/livez`         | Liveness -- always 200                             |
| GET    | `/readyz`        | Readiness -- 200 once NATS KV buckets are reachable |
| GET    | `/metrics`       | Prometheus exposition (anonymized labels)         |

## Quick start

```bash
cp .env.example .env
# Edit .env with your JWT_SECRET and OIDC provider config
docker compose up --build
```

There is **no verification bypass**: every id_token must verify against a configured provider, in every environment. For local development, run the pilotable test IdP from [br-e2e-harness](https://github.com/BotResources/br-e2e-harness) (`ghcr.io/botresources/br-oidc-test-idp`) and declare it like any provider — see `.env.example`. The e2e suite (`scripts/e2e/run.sh`) needs no external stack: it spawns its own `nats-server` and in-process OIDC IdPs (requires `nats-server` on `PATH`).

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full list.

OIDC providers are auto-detected at startup by scanning for `OIDC_*_DISCOVERY_URL` env vars. Each provider needs a matching `OIDC_{NAME}_CLIENT_ID`. Multiple providers can coexist (e.g. Entra + Google).

## Architecture

- **NATS KV** for refresh token storage (raw `async_nats`) and sealed bearer
  resolution from `PUBLISHED_LANGUAGE` via the `br-util-nats-fabric` Fabric (no database)
- **Multi-provider OIDC** with auto-discovery, per-provider JWKS cache, refresh on unknown `kid` (cooldown-gated, `JWKS_REFRESH_COOLDOWN_SECONDS`)
- **Token rotation** with family-based revocation (reuse detection)
- **HttpOnly cookies** with `__Host-` prefix in production
- **Silent refresh** on expired access tokens via `auth_check`
- **Bearer resolution** against the AEAD-sealed `br-auth-contract` wire in the
  `PUBLISHED_LANGUAGE` bucket (`identity/bearer_tokens/` prefix, ChaCha20-Poly1305,
  key from `BEARER_SEAL_KEY`). A resolved bearer returns `200` with the resolved
  actor exposed via `X-Auth-User-Id` / `X-Auth-Service-Account-Id` and
  `X-Auth-Token-Id`; an unresolved bearer fails closed with `401`. svc-auth does
  not build a Passport — it exposes the resolved actor only.
- **Observability from `br-rust-common`** — structured JSON logging, the `/livez`
  liveness route and the `/metrics` Prometheus endpoint via `br-util-observability`;
  the `/readyz` readiness gate (flipped UP once the NATS KV buckets are reachable
  at startup) via `br-util-axum-readiness`

### Why it is the way it is

| Thing | Why it is the way it is |
|---|---|
| `JWT verify` leeway = 5s (`CLOCK_SKEW_LEEWAY_SECS`) | `jsonwebtoken`'s default leeway is 60s, which silently extends every token's lifetime by a minute. 5s tolerates real clock skew without materially widening the validity window. |
| `JWKS_REFRESH_COOLDOWN_SECONDS` floored at 1s (`JWKS_REFRESH_COOLDOWN_FLOOR_SECS`) | An unknown `kid` triggers a JWKS re-fetch. A cooldown of 0 would let a stream of invalid tokens (each with a bogus `kid`) hammer the IdP's JWKS endpoint — a self-inflicted DoS amplifier. The floor keeps storm protection always on. |
| `Environment::parse` rejects unknown values | Auth fails closed: an unrecognised `ENVIRONMENT` (a typo, or a new env nobody wired up) must abort at boot, never silently degrade to the most-permissive `Local` mode. |
| Routing id_tokens on the **unverified** `iss` (`decode_jwt_payload_unverified`) | The issuer is only used to *select* the provider; the signature, issuer, and audience are then verified against that provider's JWKS and config. Picking the wrong provider on a forged `iss` cannot succeed — verification still fails. |
| Refresh rotation stores the new token **before** marking the old one used | If the order were reversed, a crash between the two writes would invalidate the old token with no replacement persisted — silently logging the user out. Store-then-mark keeps a valid token reachable at every point. |
| `mark_used` takes the KV `revision` (CAS) | Two concurrent refreshes of the same token must not both succeed: the compare-and-swap on the revision makes the second writer fail — a lost-update guard on rotation (distinct from the `used_at` replay check, which is the actual reuse-detection). |
| `/auth/token` and `/auth/refresh` return only metadata; the access/refresh tokens go in `Set-Cookie` | Credentials are never placed in a response body that a client (or a log) could read back — they ride HttpOnly cookies only. |

## Kubernetes deployment

A minimal Helm chart is published to `oci://ghcr.io/botresources/charts/br-svc-auth` alongside each image release. See [`charts/br-svc-auth/`](charts/br-svc-auth/) for the chart source and [`charts/br-svc-auth/values-local.yaml`](charts/br-svc-auth/values-local.yaml) for a K3d example.

```bash
kubectl create secret generic br-svc-auth-jwt \
  --from-literal=secret="$(openssl rand -base64 48)"

helm install auth \
  oci://ghcr.io/botresources/charts/br-svc-auth \
  --version 0.1.0 \
  -f my-values.yaml
```

## Development

### Git hooks

Enable the repo's hooks (fmt + clippy + secret scan pre-commit, conventional-commit lint on commit-msg):

```bash
git config core.hooksPath .githooks
```

### Publishing

Bump `version` in `Cargo.toml`, add a matching `## {version}` entry in `CHANGELOG.md`, push to `main`. CI auto-tags `v{version}` and CD publishes the multi-arch image to `ghcr.io/botresources/br-svc-auth:{version}`.

Manual publish / dry-run:

```bash
./scripts/publish.sh --local-image  # runnable docker image for host arch
./scripts/publish.sh --dry-run      # binary only, no docker, no push
./scripts/publish.sh --check-only   # fmt + clippy + tests + audit only
./scripts/publish.sh                # full publish (requires tag + GHCR_TOKEN)
```

`--local-image` produces `ghcr.io/botresources/br-svc-auth:{version}-local` — cross-compiled for the host arch, packaged into the runtime image. Works on any branch, no checks, for fast iteration.

## License

Apache-2.0 — see [LICENSE](LICENSE).
