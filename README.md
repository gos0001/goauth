# goauth

An identity service in Go: users, passwords, sessions, and Ed25519-signed JWTs
that consuming services verify offline.

Vertical slices, one package per use case, wire for dependency injection, sqlc
for Postgres.

## What it does, and what it deliberately does not

goauth answers exactly one question: **who is this user**. It stores accounts,
checks passwords, manages refresh sessions, and mints access tokens.

Authorisation is not its job. Subscriptions, product roles, permissions and
entitlements live in whichever service owns them, keyed by `user_id`. Consuming
services store that id as a plain column with **no foreign key back to
goauth** — the moment another service joins against `ga_users`, this stops being
a service and becomes a shared database.

The one role it does carry is `is_admin`, a boolean governing goauth's own
`/admin` endpoints and nothing else. It is not a role list on purpose: a set of
product-scoped roles would require knowing which product each role belongs to,
which is the realm concept this service exists to avoid.

Not included in v1, each deliberately: captcha, email delivery, email
verification, invite-based registration, OAuth providers, MFA, an admin CLI.
The schema and configuration leave room for all of them.

**Consequence to know about:** with no mail delivery there is no public "forgot
password" flow. A locked-out user is recovered by an admin calling
`POST /admin/users/{id}/password`, which sets a temporary password, forces
`must_change_password`, revokes every session, and writes an audit row.

**Contents:** [Install](#install) · [Using it from another
project](#using-it-from-another-project) · [Endpoints](#endpoints) ·
[Configuration](#configuration) · [Build from source](#build-from-source) ·
[Architecture](#architecture)

## Install

Requirements: Docker, a Postgres 13+ server, and a Redis. Nothing else — no Go
toolchain, no source checkout, no migration step. The schema is compiled into the
binary; on startup goauth creates its database if it is missing, creates any
missing tables, and serves. Pointing it at a server is enough.

### Option A — Docker Compose, everything in one file

Create a directory, drop in this `docker-compose.yml`, and you are done:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: goauth
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: goauth
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U goauth"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  goauth:
    image: ghcr.io/gos0001/goauth:1
    environment:
      POSTGRES_URL: postgres://goauth:${POSTGRES_PASSWORD}@postgres:5432/goauth?sslmode=disable
      REDIS_URL: redis://redis:6379
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY:?run make jwt-key or openssl rand -base64 32}
      JWT_ISSUER: goauth
      JWT_AUDIENCE: my-app
      SUPER_ADMIN_USERNAME: superadmin
      APP_ENV: production
      # Machine-facing admin listener. Bound to all interfaces so sibling
      # containers can reach http://goauth:8081 — and kept private by simply
      # not publishing the port below.
      ADMIN_ADDR: "0.0.0.0:8081"
      ADMIN_TOKEN: ${ADMIN_TOKEN:-}
    ports:
      - "8080:8080"
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

Then a `.env` beside it:

```bash
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_PRIVATE_KEY=$(openssl rand -base64 32)
ADMIN_TOKEN=$(openssl rand -base64 32)
EOF
chmod 600 .env

docker compose up -d
docker compose logs goauth | grep 'generated password'
```

Note the database password is **hex, not base64**. It goes inside a connection
URL, and base64 output contains `/` and `+` — a `/` ends the authority section,
so the driver reads the rest of the password as a hostname and fails with a
baffling "invalid port" error. Hex avoids the whole question. If you bring your
own password and it contains any of `/ + @ : ? # %`, percent-encode it in
`POSTGRES_URL`.

`JWT_PRIVATE_KEY` and `ADMIN_TOKEN` stay base64: the first must decode to
exactly 32 bytes, and neither ever appears in a URL.

The `${VAR:?message}` form is deliberate: compose refuses to start rather than
silently substituting an empty string, which is how an installation ends up with
no signing key and no way to notice.

### Option B — one container against an existing Postgres and Redis

```bash
docker run -d --name goauth --restart unless-stopped -p 8080:8080 \
  -e POSTGRES_URL='postgres://user:pass@host:5432/goauth?sslmode=disable' \
  -e REDIS_URL='redis://host:6379' \
  -e JWT_PRIVATE_KEY="$(openssl rand -base64 32)" \
  -e JWT_AUDIENCE=my-app \
  -e SUPER_ADMIN_USERNAME=superadmin \
  -e APP_ENV=production \
  ghcr.io/gos0001/goauth:1

docker logs goauth | grep 'generated password'
```

The database does not need to exist first — goauth creates it. Where the role is
not allowed to (`NOCREATEDB`, common on managed Postgres), create it once by hand
and goauth will use it as-is:

```sql
CREATE DATABASE goauth;
```

### Check it came up

```bash
curl -s localhost:8080/healthz
# {"data":{"status":"ok","postgres":"ok","redis":"ok"}}

curl -s -X POST localhost:8080/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","identifier":"superadmin","password":"<from the log>"}'
```

The response carries `"must_change_password": true`. Change it straight away —
that is what retires the password that was printed to the log:

```bash
curl -s -X POST localhost:8080/auth/password \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"<generated>","new_password":"<your own, 12+ chars>"}'
```

### About the two secrets

`SUPER_ADMIN_PASSWORD` left empty means the service generates one and prints it
**once**, on the run that creates the account. The account carries
`must_change_password`, so that value stops working as soon as the real admin
logs in. It does reach the container logs, so set it explicitly where logs ship
somewhere you would rather it not go.

`JWT_PRIVATE_KEY` is required and deliberately never generated. Generating it
per process would invalidate every issued token on restart and make replicas
sign with different keys; persisting a generated key in the database — what Dex
and Keycloak do — would put the private key in every database backup. Keep it
wherever your other secrets live, and reuse the same value across restarts and
replicas.

### Behind a reverse proxy

Terminate TLS at the proxy and forward to `8080`. Then tell goauth whom to
believe about client addresses, or every rate limit will count the proxy instead
of the caller:

```
# nginx, Traefik, Caddy on the same host or a private network
TRUSTED_PROXIES=private
CLIENT_IP_HEADER=X-Forwarded-For

# Cloudflare in front
TRUSTED_PROXIES=cloudflare
CLIENT_IP_HEADER=CF-Connecting-IP
```

Leaving both empty is the safe default: no forwarding header is believed at all.
See [Client IP behind a proxy](#client-ip-behind-a-proxy) for why this must be
configured rather than guessed.

### Production checklist

- `APP_ENV=production` — switches the logger to JSON.
- A `JWT_PRIVATE_KEY` unique to this deployment. Never reuse a development key.
- `JWT_AUDIENCE` set per application, and matched in every consumer.
- `AUTH_REGISTRATION_MODE` left at `closed` unless you actually want public
  sign-up; accounts are then created through `/admin/users`.
- `ADMIN_TOKEN` set only if machines need the admin API. Empty means the private
  listener never starts, which is the right default when nothing uses it.
- Port `8081` **not** published — it is reachable from sibling containers and
  nowhere else.
- `TRUSTED_PROXIES` / `CLIENT_IP_HEADER` matching the actual topology, plus a
  firewall so the origin only accepts connections from the edge. Application
  config alone does not stop someone talking to the origin directly.
- Back up Postgres. It holds users, sessions and the audit trail; Redis holds
  only rate-limit counters and can be lost without consequence.

### Upgrading

```bash
docker compose pull goauth && docker compose up -d goauth
```

The schema is checked on startup, before the listeners open, and anything missing
is created. It runs under a Postgres advisory lock, so several replicas may start
against one database — or against no database at all — simultaneously: exactly
one creates it, exactly one creates the admin, and the rest carry on.

Set `DB_AUTO_SCHEMA=false` where a deployment pipeline owns schema changes, and
`DB_AUTO_CREATE=false` where the database is provisioned by other tooling. With
either off, goauth refuses to serve rather than running against something it does
not recognise.

### Image tags

| Tag | Moves when | Use it for |
|---|---|---|
| `1`, `1.2`, `1.2.3` | a `v*` git tag is pushed | anything you deploy |
| `latest` | a `v*` git tag is pushed | trying it out |
| `edge` | any push to `main` | following development |
| `sha-abc1234` | every build | pinning an exact commit |

Note there is no `v` on the image tags: git tag `v1.2.3` publishes `1.2.3`,
`1.2` and `1`, the same convention the official Docker images use.

`latest` follows **releases, not `main`** — otherwise the first merge after a
release would silently replace the released image for everyone pulling it.
`edge` is the tag for the newest commit on `main`.

Pin at least a major (`:1`) for anything you will not be watching, and a digest
(`@sha256:…`) where the image must not move at all. Built for `linux/amd64` and
`linux/arm64`.

`docker run --rm ghcr.io/gos0001/goauth:1 version` prints the version and commit
a given image was built from.

## Using it from another project

### Give goauth its own database

Not its own tables in your database — **its own database**. One Postgres server
is fine, and usually right; a second Postgres container buys nothing but another
thing to back up.

Three reasons, in order of how badly they bite:

- **Table names are the only thing keeping the two apart otherwise.** goauth
  prefixes everything with `ga_`, so a shared database happens to work — until
  the day your application wants a table of its own by that name, or a `DROP
  SCHEMA public CASCADE` in one service takes the other with it.
- **A cross-database join is impossible in Postgres.** That turns "never join
  against `ga_users`" from a convention that erodes under deadline pressure into
  a constraint the database enforces for you.
- **goauth's data can be dumped, restored, and moved independently** of the
  product's. Separate lifecycles want separate `pg_dump` files.

goauth creates the database itself when the role is allowed to, so in the compose
below nothing needs pre-creating. Where the role is restricted — `NOCREATEDB`, as
managed Postgres often gives you — create it once with an init script, which runs
on an empty data volume:

```
initdb/01-databases.sql
```

```sql
CREATE DATABASE goauth;
CREATE DATABASE myapp;
```

### Compose

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set it in .env}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      # Optional: goauth creates its own database. This is for pre-creating
      # your application's, and for roles that may not create databases.
      # Runs only on an empty data volume.
      - ./initdb:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  auth:
    image: ghcr.io/gos0001/goauth:1
    environment:
      # its own database ────────────────────┐
      POSTGRES_URL: postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/goauth?sslmode=disable
      REDIS_URL: redis://redis:6379
      JWT_PRIVATE_KEY: ${GOAUTH_JWT_PRIVATE_KEY:?run openssl rand -base64 32}
      JWT_AUDIENCE: my-app
      SUPER_ADMIN_USERNAME: superadmin
      APP_ENV: production
      # Reachable only from this network — do not publish 8081.
      ADMIN_ADDR: "0.0.0.0:8081"
    ports:
      - "8080:8080"
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }

  myapp:
    image: myapp:latest
    environment:
      # yours ───────────────────────────────┐
      DATABASE_URL: postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/myapp?sslmode=disable
      GOAUTH_JWKS_URL: http://auth:8080/.well-known/jwks.json
      GOAUTH_AUDIENCE: my-app
    depends_on:
      auth: { condition: service_started }
```

Pin a major or exact version — `latest` is fine for trying it out and a poor
idea for anything you will not be watching. For deployments that must not move
underneath you, pin the digest instead, since a tag can be repointed and a digest
cannot:

```
ghcr.io/gos0001/goauth@sha256:<digest>
```

### Linking your users to goauth

With separate databases there is no foreign key to reach for, which is the point.
The application keeps its own user row and stores goauth's id beside it:

```sql
CREATE TABLE users (
    id          bigserial PRIMARY KEY,
    external_id uuid NOT NULL UNIQUE,   -- goauth's user id: the JWT `sub`
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    user_id    bigint PRIMARY KEY REFERENCES users (id),
    plan       text NOT NULL,
    expires_at timestamptz
);
```

Four decisions in that schema, each one people get wrong at least once:

- **Your primary key stays yours.** Subscriptions, roles, orders and everything
  else reference `users.id`, never the auth UUID. That is what makes swapping the
  auth provider later a change to one column rather than to every foreign key in
  the schema.
- **`external_id` is unique and never reused.** It is the `sub` claim, read with
  `authclient.UserID(c)`.
- **The row is created on first sighting**, not pushed by goauth. On the first
  authenticated request, upsert and carry on — goauth never learns that your
  application exists, which is what keeps it reusable across projects.
- **Deletion is two-sided.** goauth soft-deletes and clears identifiers; your row
  survives, and you decide whether that means anonymise or remove.

```go
func (m *Users) Resolve(c *gin.Context) (int64, error) {
    var id int64
    err := m.db.QueryRow(c, `
        INSERT INTO users (external_id) VALUES ($1)
        ON CONFLICT (external_id) DO UPDATE SET external_id = EXCLUDED.external_id
        RETURNING id`,
        authclient.UserID(c),
    ).Scan(&id)
    return id, err
}
```

The `DO UPDATE` that assigns the column to itself looks pointless but is not:
`DO NOTHING` returns no row on conflict, so a returning-upsert needs an update
that always fires.

Then verify tokens in that project's Go service:

```go
import "github.com/gos0001/goauth/pkg/authclient"

mw, err := authclient.New(authclient.Config{
    JWKSURL:  "http://auth:8080/.well-known/jwks.json",
    Issuer:   "goauth",
    Audience: "my-app",
})
r.Use(mw.Require())
```

Set `JWT_AUDIENCE` per consuming application and match it in `Audience` above:
that is what stops a token minted for one of your projects being accepted by
another.

Store `user_id` from `authclient.UserID(c)` as a plain column. Keep that
project's roles, subscriptions and permissions in its own tables — goauth
answers who the caller is, and nothing else.

## Build from source

Requires Go 1.25+, Docker for the dependencies, and the tools `make tools`
installs (air, wire, sqlc, golangci-lint).

```bash
git clone https://github.com/gos0001/goauth.git
cd goauth

make tools
cp .env.example .env.development
make jwt-key                   # paste the result into JWT_PRIVATE_KEY
make admin-token               # paste the result into ADMIN_TOKEN

make docker-up                 # postgres + redis
make generate                  # sqlc, then wire
make dev                       # http://localhost:8080, rebuilds on change
```

`make run` starts it once without hot reload; `make build` puts a binary in
`./bin/app`. A binary built this way needs the same environment variables as the
image — it is the identical program.

`.env.development` is gitignored because it holds a real signing key; only
`.env.example` is committed. The database and its tables are created on startup
here too, so `make docker-up && make dev` against an empty Postgres is enough.

On first boot, `SUPER_ADMIN_USERNAME` / `SUPER_ADMIN_PASSWORD` create the
bootstrap administrator — only if the installation has no active admin. That
account is forced to change its password on first login, because the bootstrap
password is visible in the process environment, `docker inspect`, shell history
and CI logs.

### Building and publishing the image

```bash
make image                      # single-arch, into the local daemon
make image-run                  # run it against the compose Postgres and Redis
export GITHUB_TOKEN=...         # a PAT with write:packages
make image-login
make image-push VERSION=v1.0.0  # linux/amd64 + linux/arm64 to GHCR
```

Pushing to `main` or a `v*` tag does the same through Actions
(`.github/workflows/ci.yml`), after `go vet` and the race-enabled test suite
pass — so a broken build never reaches the registry. Pull requests build both
architectures but never publish.

**One manual step after the very first successful run:** GHCR creates a new
package as *private* no matter the repository's visibility, so a pull from
anywhere else answers `401`. Open GitHub → Packages → `goauth` → Package
settings → Change visibility → Public. It only has to be done once.

## Endpoints

### Public

| Route | Notes |
|---|---|
| `POST /auth/token` | `grant_type: password \| refresh_token` |
| `POST /auth/register` | only registered when `AUTH_REGISTRATION_MODE=open` |
| `GET /auth/settings` | registration mode and password floor, for the frontend |
| `GET /.well-known/jwks.json` | public verification keys |
| `GET /healthz` | |

### Bearer token required

| Route | Notes |
|---|---|
| `GET /auth/me` | read from the database, not echoed from the token |
| `GET /auth/sessions` | "my devices" |
| `POST /auth/password` | needs the current password; returns a fresh pair |
| `POST /auth/revoke` | log out this device |
| `POST /auth/logout-all` | log out everywhere |

### Admin

The same handlers are reachable two ways, and never with the wrong credential:

- **`:8080/admin/*`** — a user's JWT, with `is_admin` re-read from the database
  on every request. This is the path a panel frontend uses.
- **`:8081/admin/*`** — the static `ADMIN_TOKEN`, for machines: scripts, CI, a
  payment webhook provisioning an account after purchase.

```
GET    /admin/users              ?q=&status=&limit=&offset=
POST   /admin/users
GET    /admin/users/{id}
PATCH  /admin/users/{id}         identifiers, status, is_admin
DELETE /admin/users/{id}         soft delete
POST   /admin/users/{id}/password
GET    /admin/users/{id}/sessions
DELETE /admin/users/{id}/sessions
GET    /admin/audit
```

Every rejection on the admin surface — no token, bad token, valid token without
rights — answers `404`, so an unauthorised caller cannot even learn that the
surface exists. The static token is never accepted on the public listener: a
browser cannot hold a shared, non-expiring credential safely.

`PATCH`, `DELETE` and the password endpoint additionally require that the acting
admin presented their password within `ADMIN_REAUTH_WINDOW`. A hijacked admin tab
can therefore read, but not destroy. Machine callers are exempt — they present
their credential on every request.

## Why Ed25519 rather than a shared secret

With a symmetric algorithm, every service that can verify a token can also mint
one: a single compromised consumer forges any identity, and rotating the secret
means redeploying everything at once.

Here goauth holds the only private key. Consumers fetch the JWKS once and verify
offline — no per-request call back, and goauth being down does not invalidate
tokens already issued. Rotation is a two-step deploy: move the old public key
into `JWT_PREVIOUS_PUBLIC_KEYS`, and tokens signed by it keep verifying until
they expire while new ones use the new key. Consumers need no coordination,
because a token names its key in the `kid` header.

## Sessions and refresh rotation

Refresh tokens are opaque random strings; only their SHA-256 is stored, so a
database dump hands over nothing replayable. They live in Postgres rather than
Redis because reuse detection needs the family history, "my devices" needs a
queryable list, and a cache flush must not log everyone out.

Every refresh is single-use. Presenting one that was already spent means two
parties hold it, so **the entire session family is destroyed** — that is the
only available signal that a refresh token leaked.

An access token cannot be revoked before it expires; that is inherent to
stateless tokens and is why the TTL is minutes. Anything needing immediate
effect reads the database instead, which is what the admin guard and every login
do — so blocking an account takes effect at once.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ADDR` | `:8080` | public listener |
| `ADMIN_ADDR` | `127.0.0.1:8081` | machine-facing admin listener |
| `ADMIN_TOKEN` | — | empty disables the admin listener entirely |
| `ADMIN_REAUTH_WINDOW` | `15m` | sudo window for destructive admin calls |
| `POSTGRES_URL` | — | required |
| `REDIS_URL` | — | required; used for rate limiting |
| `DB_AUTO_CREATE` | `true` | create the database if it does not exist |
| `DB_AUTO_SCHEMA` | `true` | create missing tables at startup |
| `JWT_PRIVATE_KEY` | — | required; base64 of a 32-byte ed25519 seed |
| `JWT_PREVIOUS_PUBLIC_KEYS` | — | retired keys, published but never used to sign |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `goauth` | verified on every token |
| `JWT_ACCESS_TTL` | `15m` | |
| `JWT_REFRESH_TTL` | `720h` | |
| `AUTH_REGISTRATION_MODE` | `closed` | `closed` or `open` |
| `AUTH_MIN_PASSWORD_LEN` | `12` | length is the only rule; see below |
| `SUPER_ADMIN_USERNAME` / `_PASSWORD` / `_EMAIL` | — | bootstrap admin |
| `TRUSTED_PROXIES` | — | CIDRs, or `cloudflare`, or `private` |
| `CLIENT_IP_HEADER` | — | `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For` |
| `RATELIMIT_LOGIN_IP` | `100/15m` | per IP bucket |
| `RATELIMIT_LOGIN_PAIR` | `10/15m` | per IP + account |
| `RATELIMIT_FAIL_CLOSED` | `true` | Redis down ⇒ refuse logins |
| `AUDIT_RETENTION` | `720h` | delete audit entries older than this; `0` keeps everything |
| `AUDIT_MAX_ROWS` | `0` | hard cap on audit rows, newest kept; `0` disables |
| `AUDIT_CLEANUP_INTERVAL` | `6h` | how often the audit sweep runs; `0` disables |
| `SESSION_CLEANUP_INTERVAL` | `1h` | how often expired sessions are swept; `0` disables |

Password rules are a length floor and nothing else. Composition requirements
(a digit, a symbol, mixed case) push people toward predictable substitutions and
measurably weaken real passwords.

### Client IP behind a proxy

`X-Forwarded-For` is an ordinary header anyone can set. Believing it lets an
attacker rotate a fake address per request — defeating rate limiting — or send a
victim's address to burn the victim's bucket. So a header is read **only** when
the peer is a configured trusted proxy, and `X-Forwarded-For` is parsed right to
left, taking the first untrusted hop.

```
TRUSTED_PROXIES=cloudflare
CLIENT_IP_HEADER=CF-Connecting-IP
```

Empty — the default — means no header is ever trusted. Note that application
config is not enough on its own: also firewall the origin so it only accepts
connections from the edge, or the edge is simply bypassed.

### Two listeners

`APP_ADDR=:8080` binds every interface. `ADMIN_ADDR=127.0.0.1:8081` binds
loopback only, so it cannot be exposed by a mistaken ingress rule the way a path
prefix on a shared port could.

Inside Docker, `127.0.0.1` is the *container's* loopback and unreachable from
sibling containers — set `ADMIN_ADDR=0.0.0.0:8081` there and keep it private by
not publishing the port. What isolates it is the absence of a `ports:` entry.

## Layout

```
goauth/
├── cmd/                        entrypoint, two listeners, wire graph
├── internal/
│   ├── domain/                 pure models, sentinel errors, identifier rules
│   ├── usecases/auth/          public and bearer-authenticated use cases
│   ├── usecases/admin/         admin use cases
│   ├── usecases/seed_super_admin/
│   ├── service/tokens/         issuing and rotating pairs
│   ├── service/audit/          best-effort audit writes
│   ├── middleware/             real IP, rate limit, auth, admin guards
│   ├── controller/http_v1/     public router
│   ├── controller/admin_v1/    admin routes + the private listener
│   ├── adapter/postgres/       sqlc queries, generated code, error mapping
│   └── orchestrators/bootstrap/
├── .github/workflows/          test, then multi-arch build and push to GHCR
├── pkg/
│   ├── dbschema/               creates missing tables at startup
│   ├── token/                  Ed25519 signing, JWKS
│   ├── passwordhash/           argon2id, PHC encoding
│   ├── realip/                 trusted-proxy aware client IP
│   ├── ratelimit/              Redis counters and backoff
│   ├── authclient/             what consuming services import
│   └── http_server/            response envelope, request-scoped values
├── schema/                     schema.sql + embed.go compiling it in
└── sqlc.yaml
```

## Database

Three tables — `ga_users`, `ga_sessions`, `ga_audit_log` — in **goauth's own
database**. See [Give goauth its own database](#give-goauth-its-own-database).

Queries live in `internal/adapter/postgres/queries/*.sql` and are compiled by
sqlc into `internal/adapter/postgres/generated/` — never edit that directory,
and never write raw SQL strings in Go.

The order matters: edit `schema/schema.sql`, then regenerate. `make generate`
runs sqlc before wire because wire cannot compile the adapter until the generated
package exists.

`schema/schema.sql` is compiled into the binary by `schema/embed.go` and executed
at startup by `pkg/dbschema`, under a Postgres advisory lock so concurrent
replicas do not collide. sqlc validates the queries against the same file, so the
schema the service creates and the schema the generated code assumes cannot
drift.

There is no migration tool and no version table. Every statement is idempotent —
`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS` — so the file is safe
to run on every start. **Adding to it later means adding idempotent statements**:
a bare `CREATE TABLE IF NOT EXISTS` will not add a column to a table that already
exists, because the whole statement is skipped. Use `ALTER TABLE … ADD COLUMN IF
NOT EXISTS` for that.

### Retention

Two tables grow on their own, so both are swept by `internal/orchestrators/cron`
on a plain ticker — no scheduler, no cron library.

`ga_audit_log` is the noisy one: it records every login, every failed login and
every token refresh, so with a 15-minute access TTL a single active user adds
roughly four rows an hour, nearly all of them `session.refreshed`. Entries older
than `AUDIT_RETENTION` are deleted, and `AUDIT_MAX_ROWS` caps the table
regardless of age.

`ga_sessions` keeps expired rows because rotation marks a session used rather
than removing it; `SESSION_CLEANUP_INTERVAL` sweeps them. Deleting an expired
session changes nothing security-wise — `auth_token` checks `expires_at` before
anything else.

`AUDIT_RETENTION=0` means keep everything. The zero value has to fail safe: read
the other way, it would silently erase the audit trail of every installation that
never configured one. A failing sweep is logged and the loop continues —
housekeeping must not be able to take down a service that is serving correctly.

The adapter maps storage failures onto domain errors — `pgx.ErrNoRows` becomes a
not-found error, a `23505` unique violation becomes `domain.ErrAlreadyExists` —
so use cases branch on domain errors alone.

Identifiers are plain `text`, normalised (trimmed, lowercased) in Go before they
reach the database. Usernames are `^[a-z0-9_]{3,32}$`, which keeps out Unicode
confusables and guarantees a username can never contain `@` and shadow an email.

## Adding a use case

Copy the nearest existing package — `internal/usecases/auth/auth_me/` is the
smallest complete one — and change it:

```
internal/usecases/<group>/<name>/
├── usecase.go   Usecase struct, adapter interfaces, New, Execute
├── dto.go       Input, Output, Validate
├── config.go    envconfig struct       (only if the package reads env vars)
├── http_v1.go   the JSON handler       (only if an HTTP caller exists)
└── wire.go      var Set = wire.NewSet(...)
```

Then register it: add the import and the `Set` to `cmd/wire.go`, and the import,
constructor parameter and route to `internal/controller/http_v1/controller.go`.
Both files carry `// codegen:` comments marking where each piece goes. Finish
with `wire ./cmd/`.

Register the `Set` and its route in the same change — wire fails with *unused
provider set* if a set is reachable but nothing consumes it.

Package names must be globally unique, because wire aliases packages by name:
`user_get`, never `get`.

## Make targets

| Target | Does |
|---|---|
| `dev` | air hot reload |
| `build` / `build-prod` | binary into `./bin/app` |
| `generate` | `sqlc generate` then `wire ./cmd/` |
| `test` | `go test ./... -race` |
| `lint` | golangci-lint |
| `jwt-key` / `admin-token` | generate a credential |
| `docker-up` / `docker-down` | dependencies via compose |
| `image` | build the container image locally |
| `image-login` / `image-push` | publish multi-arch to GHCR |
| `image-run` | run the local image against the compose services |

## Architecture

One package per use case, with a single `Execute`. Domain types are the contract
between layers. Adapter interfaces are declared in the use case that needs them,
listing only the methods it uses. Controllers route and nothing else. Handlers
answer through `pkg/http_server`, so every response is `{"data":...}` or
`{"error":...}` — the one exception is the JWKS endpoint, which must serve the
standard document generic clients expect. `pkg/` never imports
`internal/domain`. Config is per package.

The full contract lives in `.claude/skills/architecture/SKILL.md`.

## Generated files

Do not edit by hand:

- `cmd/wire_gen.go` — `wire ./cmd/`
- `internal/adapter/postgres/generated/` — `sqlc generate`

## License

MIT — see [LICENSE](LICENSE).
