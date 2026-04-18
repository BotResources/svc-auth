# svc-auth

Portable, self-contained REST authentication gatekeeper. Zero external dependencies beyond NATS.

Proves identity ("the human behind this request controls this email") via multi-provider OIDC, signs internal JWTs, and validates bearer tokens. Does **not** manage users, permissions, or sessions -- that's the consuming project's responsibility.

## Endpoints

| Method | Path             | Description                                      |
|--------|------------------|--------------------------------------------------|
| POST   | `/auth/token`    | Exchange OIDC id_token for internal JWT (cookies) |
| POST   | `/auth/refresh`  | Rotate refresh token, get new access token        |
| GET    | `/auth/check`    | nginx `auth_request` -- validate JWT or bearer    |
| POST   | `/auth/logout`   | Revoke refresh token family, clear cookies        |
| GET    | `/health`        | Health check (NATS KV reachability)               |

## Quick start

```bash
cp .env.example .env
# Edit .env with your JWT_SECRET and OIDC provider config
docker compose up --build
```

For local development without an OIDC provider, set `ALLOW_INSECURE=true`.

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full list.

OIDC providers are auto-detected at startup by scanning for `OIDC_*_DISCOVERY_URL` env vars. Each provider needs a matching `OIDC_{NAME}_CLIENT_ID`. Multiple providers can coexist (e.g. Entra + Google).

## Architecture

- **NATS KV** for refresh token storage and bearer token validation (no database)
- **Multi-provider OIDC** with auto-discovery
- **Token rotation** with family-based revocation (reuse detection)
- **HttpOnly cookies** with `__Host-` prefix in production
- **Silent refresh** on expired access tokens via `auth_check`
- **Bearer token validation** via SHA-256 hash lookup in NATS KV

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
