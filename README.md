# svc-auth

Portable, self-contained REST authentication gatekeeper. Zero infrastructure dependencies beyond NATS (no database).

Proves identity ("the human behind this request controls this email") via multi-provider OIDC, signs internal JWTs, and validates bearer tokens. Does **not** manage users, permissions, or sessions -- that's the consuming project's responsibility.

## Endpoints

| Method | Path             | Description                                      |
|--------|------------------|--------------------------------------------------|
| POST   | `/auth/token`    | Exchange OIDC id_token for internal JWT (cookies) |
| POST   | `/auth/refresh`  | Rotate refresh token, get new access token        |
| GET    | `/auth/check`    | nginx `auth_request` -- validate JWT or bearer    |
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

There is **no verification bypass**: every id_token must verify against a configured provider, in every environment. For local development or e2e, run the pilotable test IdP from [br-e2e-harness](https://github.com/BotResources/br-e2e-harness) (`ghcr.io/botresources/br-oidc-test-idp`) and declare it like any provider — see `docker-compose.e2e.yml` and `.env.example`.

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full list.

OIDC providers are auto-detected at startup by scanning for `OIDC_*_DISCOVERY_URL` env vars. Each provider needs a matching `OIDC_{NAME}_CLIENT_ID`. Multiple providers can coexist (e.g. Entra + Google).

## Architecture

- **NATS KV** for refresh token storage and bearer token validation (no database)
- **Multi-provider OIDC** with auto-discovery, per-provider JWKS cache, refresh on unknown `kid` (cooldown-gated, `JWKS_REFRESH_COOLDOWN_SECONDS`)
- **Token rotation** with family-based revocation (reuse detection)
- **HttpOnly cookies** with `__Host-` prefix in production
- **Silent refresh** on expired access tokens via `auth_check`
- **Bearer token validation** via SHA-256 hash lookup in NATS KV
- **Observability from `br-rust-common`** — structured JSON logging, the `/livez`
  liveness route and the `/metrics` Prometheus endpoint via `br-util-observability`;
  the `/readyz` readiness gate (flipped UP once the NATS KV buckets are reachable
  at startup) via `br-util-axum-readiness`

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

MIT
