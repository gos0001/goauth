# goauth

[![CI](https://github.com/gos0001/goauth/actions/workflows/ci.yml/badge.svg)](https://github.com/gos0001/goauth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/gos0001/goauth?label=release&sort=semver)](https://github.com/gos0001/goauth/pkgs/container/goauth)
[![Go Reference](https://pkg.go.dev/badge/github.com/gos0001/goauth.svg)](https://pkg.go.dev/github.com/gos0001/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/gos0001/goauth)](https://goreportcard.com/report/github.com/gos0001/goauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Stable: `v2.0.0`** — `ghcr.io/gos0001/goauth:2`

Identity service in a container. Users, passwords, sessions, and Ed25519-signed
JWTs your services verify offline. It answers **who is this user** and, for its
own admin surface, **who may manage whom** — your product's roles, plans and
entitlements still stay in the service that owns them.

No admin UI, no realms, no plugin system. One binary, one `config.json`; it
creates its own database, tables and role floor on start.

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
    image: ghcr.io/gos0001/goauth:2
    volumes:
      - ./config.json:/config.json:ro
    command: ["-config", "/config.json"]
    ports: ["8080:8080"]
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
    restart: unless-stopped

volumes:
  postgres_data:
```

```bash
cp config.example.json config.json

# One per environment — never reuse a development key in production.
make jwt-key     # -> token.private_key
make admin-token # -> admin.token

# Then edit config.json — inside compose the hosts are service names:
#   db.url:    postgres://postgres:<password>@postgres:5432/goauth?sslmode=disable
#   redis.url: redis://redis:6379
#   app.admin_addr: "0.0.0.0:8081" (unpublished port keeps it private)
# and set seed.username / seed.password.
docker compose up -d
```

The admin credentials are whatever you put in `config.json` — nothing is
generated and nothing is printed. Recreate the database and the same login
still works.

Three things to know:

- **goauth needs its own database** (`/goauth` above, not your app's). It creates
  it, unless the role may not — then `CREATE DATABASE goauth;` once by hand.
- **The database password is hex, not base64.** Base64 contains `/`, which ends
  the authority section of a connection URL and produces a baffling "invalid
  port" error.
- **`token.private_key` is required** and never auto-generated: a new key per
  process would invalidate every issued token on restart.

## Endpoints

| | |
|---|---|
| `POST /auth/token` | `grant_type: password \| refresh_token` |
| `POST /auth/register` | only when `auth.registration_mode = "open"` |
| `GET /auth/settings` | registration mode, for the frontend |
| `GET /.well-known/jwks.json` | public verification keys |
| `GET /healthz` | |

With a bearer token: `GET /auth/me`, `GET /auth/sessions`,
`POST /auth/password`, `POST /auth/revoke`, `POST /auth/logout-all`.

With `authcookie.enabled = true`, the token endpoints additionally speak to
browsers through cookies — see [Cookie channel](#cookie-channel): `/auth/token`
and `/auth/password` set `goauth_access` / `goauth_refresh` (HttpOnly), the
logout endpoints delete them, and the auth middleware accepts the access cookie
when no `Authorization` header was presented. The JSON body never changes.

Admin — user CRUD, block, force password, sessions, audit, roles:

```
GET|POST         /admin/users
GET|PATCH|DELETE /admin/users/{id}
POST             /admin/users/{id}/password
GET|DELETE       /admin/users/{id}/sessions
GET              /admin/audit
GET              /admin/roles
POST|PATCH|DELETE /admin/roles/{name}   (POST creates /admin/roles)
```

Reachable two ways: on `:8080` with a user JWT whose role carries the route's
permission — this is what a browser panel uses — and on `:8081` with the static
`admin.token` for machines. **Never give that token to a browser**, and do not
publish `8081`. Management actions additionally require the actor's rank to sit
strictly above the target's (superadmins excepted at the top), so an admin can
never block, delete or demote another admin.

An **expired** token answers `401 {"error":"token expired"}`, the same as
`/auth/*`, so a client refreshes and retries. Every other rejection answers a
bodiless `404`, so an unauthorised caller cannot tell the surface from a route
that does not exist — retrying those will not help.

## Roles and permissions

goauth's admin surface is gated by a role hierarchy, not a single admin flag.

**Roles** live in the database: a name, a **rank**, and a set of **permissions**
(fixed vocabulary — `users:read`, `users:create`, `users:update`,
`users:delete`, `password:set`, `sessions:read`, `sessions:revoke`,
`audit:read`, `roles:read`, `roles:manage`). The shipped floor:

| Role | Rank | Permissions |
|---|---|---|
| `superadmin` | 100 | everything, including `roles:manage` |
| `admin` | 50 | full user CRUD, sessions, password, audit |
| `manager` | 10 | `users:read`, `sessions:read` |
| `user` | 0 | none — every plain account |

Two rules make the hierarchy safe:

1. **Strictly above.** A management action on a user requires the actor's rank
   to be strictly higher than the target's. An admin can therefore never block,
   delete, reset the password of, or demote another admin — equal rank is out of
   reach in both directions. The single exception is the top: superadmins
   manage superadmins, or a redundant one could never be demoted. The
   last-active-superadmin guard still applies.
2. **You cannot grant what you do not hold.** Building or editing a role
   requires `roles:manage` *and* every permission you place into it, and the
   role's rank strictly below your own. Without the second half,
   `roles:manage` alone would be full escalation: build a role with everything
   and step into it.

Role changes are refused on your own account (`409`), and every grant lands in
the audit log.

**Custom roles** come two ways: `superadmin` creates them at runtime through
`/admin/roles` (ranks 1–99; ranks 0 and 100 are reserved for the built-ins,
which the API cannot modify or delete), or a deployment fixes them forever in
`seed.roles` — the self-hosted case where the panel just needs a user CRUD and
no role management UI at all. Seeding is idempotent and **never overwrites**:
change a role at runtime, restart, and your change stands. `is_system` roles
from the seed refuse deletion through the API.

Access tokens carry the role as a `role` claim — a hint for rendering, never an
authorisation decision: every admin request re-reads the role, rank and
permissions from the database, so a demotion takes effect on the next request,
not at token expiry.

## Logging in

```bash
curl -X POST localhost:8080/auth/token -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","identifier":"superadmin","password":"..."}'
```

Returns an access token (JWT, 15 min) and a refresh token (opaque, 30 days).
`identifier` is a username or email. Refresh tokens are **single-use** — each
exchange returns a new one, and replaying a spent one kills every session from
that login.

## Cookie channel

Opt-in with `authcookie.enabled = true`, for deployments whose main client is a
browser SPA. The same token responses then also arrive as cookies:

- `goauth_access` / `goauth_refresh` — `HttpOnly`, `Secure`, `SameSite=Strict`
  by default (`authcookie.samesite = "lax"` to allow top-level navigations from
  other sites), `Path=/`, host-only (no `Domain`), `Max-Age` matching each
  token's lifetime.
- `/auth/token` with an empty `refresh_token` in the body spends the refresh
  **cookie** instead — a browser rotates its session without ever reading the
  token. The body stays authoritative when it names one.
- `/auth/revoke` and `/auth/logout-all` delete the cookies;
  `/auth/password` replaces them with the new pair.
- Requests without an `Authorization` header authenticate from the access
  cookie. The header always wins when present.
- Cross-origin frontends need `cors.allow_domains` naming their origins — with
  the channel on, `*` is refused at startup, because browsers ignore the
  credentials header alongside a wildcard.

What this buys and what it does not: `HttpOnly` means injected script cannot
read the refresh token, so an XSS cannot export the session — it can only
drive it from inside the browser while it runs. The XSS itself is not
prevented by anything here; a `Content-Security-Policy` on the frontend is
that layer. For server-to-server, mobile and CLI clients nothing changes:
the JSON API is identical with the channel on or off.

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

Set `webhook.url` and goauth posts account lifecycle events — `user.created`,
`updated`, `blocked`, `unblocked`, `deleted`, `password_changed`,
`role_assigned` — so your service keeps its own copy of a user current without
polling.

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

Delivered events are kept for `outbox.retention` (7 days) and then removed.
Events nothing ever delivered — because delivery was switched off, or never ran —
are abandoned after `outbox.max_age` (30 days), so the table cannot grow
unbounded either way.

Verify with `webhook.secret`; `pkg/webhook.Verify` is exported for Go receivers.
The timestamp is inside the signature so a captured request cannot be replayed.
`webhook.api_key` adds a plain `X-Goauth-Api-Key` header for gateways that
filter on one — an addition to the signature, not a replacement.

## Claude Code plugin

```
/plugin marketplace add gos0001/goauth
/plugin install goauth@goauth
```

Gives Claude the integration contract inside *your* project, plus `/goauth-add`
to put the service into your compose file and `/goauth-verify` to wire token
verification into your code.

## Configuration

One JSON file, passed with `-config config.json` (see `config.example.json`
for every key with its default). No environment variables.

| Key | Default | |
|---|---|---|
| `env` | `development` | `production` for JSON logs |
| `app.addr` / `app.admin_addr` | `:8080` / `127.0.0.1:8081` | |
| `db.url` | — | required |
| `db.auto_create` / `db.auto_schema` | `true` | create the database / its tables |
| `redis.url` | — | required |
| `redis.key_prefix` / `redis.default_ttl` | `goauth:` / `1h` | namespace, so Redis can be shared |
| `token.private_key` | — | required; base64 of 32 bytes |
| `token.audience` | `goauth` | set per application and check it |
| `token.issuer` | `goauth` | |
| `token.access_ttl` / `token.refresh_ttl` | `15m` / `720h` | |
| `token.previous_public_keys` | — | retired keys, still published |
| `auth.registration_mode` | `closed` | `closed` or `open` |
| `auth.min_password_len` | `12` | |
| `auth.registration_require_email` | `false` | goauth sends no mail and cannot verify one |
| `seed.username` / `.password` / `.email` | — | seeds the first admin; applied at creation only |
| `seed.roles` | — | custom roles seeded at startup, never overwriting runtime changes; ranks 1–99 |
| `admin.token` | — | empty disables the machine listener |
| `admin.reauth_window` | `15m` | password re-entry for destructive admin calls |
| `realip.trusted_proxies` | — | CIDRs, `cloudflare`, or `private` |
| `realip.client_ip_header` | — | `CF-Connecting-IP`, `X-Forwarded-For` |
| `cors.allow_domains` | — | CORS origins; empty blocks browsers |
| `cors.max_age` | `12h` | how long a browser caches the preflight |
| `authcookie.enabled` | `false` | browser cookie channel — see [Cookie channel](#cookie-channel) |
| `authcookie.secure` | `true` | cookies are HTTPS-only; localhost stays fine |
| `authcookie.samesite` | `strict` | or `lax`, for top-level navigations from other sites |
| `ratelimit.login_ip` / `.login_pair` / `.register` | `100/15m` / `10/15m` / `20/1h` | |
| `ratelimit.fail_closed` | `true` | Redis down ⇒ refuse logins rather than allow them |
| `ratelimit.backoff_after` / `.backoff_base` / `.backoff_max` | `3` / `1s` / `60s` | per-account delay after wrong passwords, not a lock |
| `ratelimit.failure_window` | `15m` | how long those failures are remembered |
| `audit.retention` / `audit.max_rows` | `720h` / `0` | `0` keeps everything |
| `audit.cleanup_interval` | `6h` | |
| `sessions.cleanup_interval` | `1h` | |
| `webhook.url` / `.secret` / `.api_key` | — | empty disables webhooks |
| `webhook.interval` / `.batch_size` / `.timeout` | `10s` / `50` / `10s` | how often the outbox is drained, and how much per run |
| `webhook.max_attempts` / `.backoff_base` / `.backoff_max` | `10` / `10s` / `1h` | retries before an event is abandoned |
| `outbox.retention` | `168h` | how long delivered events are kept |
| `outbox.max_age` / `outbox.cleanup_interval` | `720h` / `1h` | when undelivered events are dropped |

A browser panel or SPA runs on a different origin, so it needs
`cors.allow_domains = ["https://app.example.com"]` — `https://*.example.com`
and `*` also work. Empty means no CORS headers and browsers block the call. It
governs browsers only: `curl` and server-to-server calls are unaffected, so it
is not an
access control.

Behind a proxy, set `realip.trusted_proxies` and `realip.client_ip_header` or rate limiting
counts the proxy instead of the caller. Empty is the safe default: no forwarding
header is believed.

## Development

```bash
git clone https://github.com/gos0001/goauth.git && cd goauth
make tools && cp config.example.json config.json
make jwt-key            # paste into token.private_key
make docker-up && make dev
```

`make generate` runs sqlc then wire, `make test` runs the suite with `-race`.
`make dev` runs air, which restarts the service on every `.go` or `.json`
change and passes `-config config.json`. The schema is `schema/schema.sql`,
applied at startup — every statement is idempotent.

## License

MIT — see [LICENSE](LICENSE).
