# goauth

[![CI](https://github.com/gos0001/goauth/actions/workflows/ci.yml/badge.svg)](https://github.com/gos0001/goauth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/gos0001/goauth?label=release&sort=semver)](https://github.com/gos0001/goauth/pkgs/container/goauth)
[![Go Reference](https://pkg.go.dev/badge/github.com/gos0001/goauth.svg)](https://pkg.go.dev/github.com/gos0001/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/gos0001/goauth)](https://goreportcard.com/report/github.com/gos0001/goauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Stable: `v1.4.1`** — `ghcr.io/gos0001/goauth:1`

Identity service in a container. Users, passwords, sessions, and Ed25519-signed
JWTs your services verify offline. It answers **who is this user** and nothing
else — roles, plans and permissions stay in the service that owns them.

No admin UI, no realms, no plugin system. One binary, two connection URLs; it
creates its own database and tables on start.

---

## Install

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?}
    volumes: [postgres_data:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 5

  auth:
    image: ghcr.io/gos0001/goauth:1
    environment:
      POSTGRES_URL: postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/goauth?sslmode=disable
      REDIS_URL: redis://redis:6379
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY:?}
      JWT_AUDIENCE: my-app
      SUPER_ADMIN_USERNAME: superadmin
      SUPER_ADMIN_PASSWORD: ${SUPER_ADMIN_PASSWORD:?}
      APP_ENV: production
    ports: ["8080:8080"]
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
    restart: unless-stopped

volumes:
  postgres_data:
```

```bash
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_PRIVATE_KEY=$(openssl rand -base64 32)
SUPER_ADMIN_PASSWORD=<your admin password, 12+ chars>
EOF

docker compose up -d
```

The admin credentials are whatever you put in `.env` — nothing is generated and
nothing is printed. Recreate the database and the same login still works.

Three things to know:

- **goauth needs its own database** (`/goauth` above, not your app's). It creates
  it, unless the role may not — then `CREATE DATABASE goauth;` once by hand.
- **The database password is hex, not base64.** Base64 contains `/`, which ends
  the authority section of a connection URL and produces a baffling "invalid
  port" error.
- **`JWT_PRIVATE_KEY` is required** and never auto-generated: a new key per
  process would invalidate every issued token on restart.

## Endpoints

| | |
|---|---|
| `POST /auth/token` | `grant_type: password \| refresh_token` |
| `POST /auth/register` | only when `AUTH_REGISTRATION_MODE=open` |
| `GET /auth/settings` | registration mode, for the frontend |
| `GET /.well-known/jwks.json` | public verification keys |
| `GET /healthz` | |

With a bearer token: `GET /auth/me`, `GET /auth/sessions`,
`POST /auth/password`, `POST /auth/revoke`, `POST /auth/logout-all`.

Admin — user CRUD, block, force password, sessions, audit:

```
GET|POST         /admin/users
GET|PATCH|DELETE /admin/users/{id}
POST             /admin/users/{id}/password
GET|DELETE       /admin/users/{id}/sessions
GET              /admin/audit
```

Reachable two ways: on `:8080` with a user JWT whose account has `is_admin` —
this is what a browser panel uses — and on `:8081` with the static `ADMIN_TOKEN`
for machines. **Never give that token to a browser**, and do not publish `8081`.
Every rejection answers `404`.

## Logging in

```bash
curl -X POST localhost:8080/auth/token -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","identifier":"superadmin","password":"..."}'
```

Returns an access token (JWT, 15 min) and a refresh token (opaque, 30 days).
`identifier` is a username or email. Refresh tokens are **single-use** — each
exchange returns a new one, and replaying a spent one kills every session from
that login.

## Verifying tokens

In your service, **offline** against the JWKS. Never call goauth per request.

```go
import "github.com/gos0001/goauth/pkg/authclient"

mw, _ := authclient.New(authclient.Config{
    JWKSURL:  "http://auth:8080/.well-known/jwks.json",
    Issuer:   "goauth",
    Audience: "my-app",
})
r.Use(mw.Require())
userID := authclient.UserID(c)   // the `sub` claim
```

Any language works — `jose` for Node, `joserfc` for Python. Check the signature,
`iss`, `aud` and `exp`, and restrict the algorithm to `EdDSA`.

## Linking your users

Your service keeps its own user row and stores goauth's id beside it:

```sql
CREATE TABLE users (
    id          bigserial PRIMARY KEY,
    external_id uuid NOT NULL UNIQUE,   -- goauth's user id: the JWT `sub`
    created_at  timestamptz NOT NULL DEFAULT now()
);
```

Upsert on the first authenticated request. Your subscriptions, roles and orders
reference `users.id`, never the auth UUID — that is what makes changing auth
provider a one-column change. No foreign key into goauth: separate databases
make one impossible, deliberately.

## Webhooks

Set `WEBHOOK_URL` and goauth posts account lifecycle events — `user.created`,
`updated`, `blocked`, `unblocked`, `deleted`, `password_changed`,
`admin_granted`, `admin_revoked` — so your service keeps its own copy of a user
current without polling.

Events are written in the same transaction as the change, then delivered by a
background worker with exponential backoff. A receiver being down delays events;
it never loses them.

```
X-Goauth-Signature: sha256=<hmac of "<timestamp>.<body>">
X-Goauth-Timestamp: 1786550000
X-Goauth-Event:     user.created
X-Goauth-Event-Id:  <uuid>          # stable across retries — deduplicate on it
X-Goauth-Attempt:   1
```

Delivered events are kept for `WEBHOOK_RETENTION` (7 days) and then removed.
Events nothing ever delivered — because delivery was switched off, or never ran —
are abandoned after `OUTBOX_MAX_AGE` (30 days), so the table cannot grow
unbounded either way.

Verify with `WEBHOOK_SECRET`; `pkg/webhook.Verify` is exported for Go receivers.
The timestamp is inside the signature so a captured request cannot be replayed.
`WEBHOOK_API_KEY` adds a plain `X-Goauth-Api-Key` header for gateways that filter
on one — an addition to the signature, not a replacement.

## Claude Code plugin

```
/plugin marketplace add gos0001/goauth
/plugin install goauth@goauth
```

Gives Claude the integration contract inside *your* project, plus `/goauth-add`
to put the service into your compose file and `/goauth-verify` to wire token
verification into your code.

## Configuration

| Variable | Default | |
|---|---|---|
| `POSTGRES_URL` | — | required |
| `REDIS_URL` | — | required |
| `JWT_PRIVATE_KEY` | — | required; base64 of 32 bytes |
| `JWT_AUDIENCE` | `goauth` | set per application and check it |
| `JWT_ISSUER` | `goauth` | |
| `JWT_ACCESS_TTL` / `JWT_REFRESH_TTL` | `15m` / `720h` | |
| `JWT_PREVIOUS_PUBLIC_KEYS` | — | retired keys, still published |
| `AUTH_REGISTRATION_MODE` | `closed` | `closed` or `open` |
| `AUTH_MIN_PASSWORD_LEN` | `12` | |
| `SUPER_ADMIN_USERNAME` / `_PASSWORD` / `_EMAIL` | — | seeds the first admin; applied at creation only |
| `APP_ADDR` / `ADMIN_ADDR` | `:8080` / `127.0.0.1:8081` | |
| `ADMIN_TOKEN` | — | empty disables the machine listener |
| `ADMIN_REAUTH_WINDOW` | `15m` | password re-entry for destructive admin calls |
| `APP_ENV` | `development` | `production` for JSON logs |
| `DB_AUTO_CREATE` / `DB_AUTO_SCHEMA` | `true` | create the database / its tables |
| `ALLOW_DOMAINS` | — | CORS origins; empty blocks browsers |
| `TRUSTED_PROXIES` | — | CIDRs, `cloudflare`, or `private` |
| `CLIENT_IP_HEADER` | — | `CF-Connecting-IP`, `X-Forwarded-For` |
| `RATELIMIT_LOGIN_IP` / `_PAIR` | `100/15m` / `10/15m` | |
| `AUDIT_RETENTION` / `AUDIT_MAX_ROWS` | `720h` / `0` | `0` keeps everything |
| `WEBHOOK_URL` / `_SECRET` / `_API_KEY` | — | empty disables webhooks |

A browser panel or SPA runs on a different origin, so it needs
`ALLOW_DOMAINS=https://app.example.com` — `https://*.example.com` and `*` also
work. Empty means no CORS headers and browsers block the call. It governs
browsers only: `curl` and server-to-server calls are unaffected, so it is not an
access control.

Behind a proxy, set `TRUSTED_PROXIES` and `CLIENT_IP_HEADER` or rate limiting
counts the proxy instead of the caller. Empty is the safe default: no forwarding
header is believed.

## Development

```bash
git clone https://github.com/gos0001/goauth.git && cd goauth
make tools && cp .env.example .env.development
make jwt-key            # paste into JWT_PRIVATE_KEY
make docker-up && make dev
```

`make generate` runs sqlc then wire, `make test` runs the suite with `-race`.
The schema is `schema/schema.sql`, applied at startup — every statement is
idempotent, so changes are added as `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.

## License

MIT — see [LICENSE](LICENSE).
