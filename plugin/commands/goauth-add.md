---
description: Add the goauth identity service to this project — compose service, generated secrets, and the users table that references it
---

Add goauth to **this** project. Read the `goauth` skill first for the integration
contract; this command applies it.

You are working in someone's own repository, not in goauth's. Nothing is
overwritten without saying so first.

## 1. Look before writing

Establish, by reading rather than assuming:

- Is there a `docker-compose.yml` (or `compose.yaml`)? Which services exist, and
  is there already a `postgres` and a `redis`?
- Is there a `.env`, and is it gitignored? If it is tracked, say so — the
  generated signing key must not be committed.
- What migration tool does this project use, if any, and where do its files live?
- Is goauth already present? If so, report what is configured and stop.

## 2. Propose, then write

Show the user what you intend to add and wait for confirmation. Then:

**The compose service.** Add `auth` alongside the existing services; do not
rewrite the file. It must use its **own database** — `/goauth` in the URL, not
the application's:

```yaml
  auth:
    image: ghcr.io/gos0001/goauth:1
    environment:
      POSTGRES_URL: postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/goauth?sslmode=disable
      REDIS_URL: redis://redis:6379
      JWT_PRIVATE_KEY: ${GOAUTH_JWT_PRIVATE_KEY:?generate with openssl rand -base64 32}
      JWT_ISSUER: goauth
      JWT_AUDIENCE: <this project's name>
      SUPER_ADMIN_USERNAME: superadmin
      SUPER_ADMIN_PASSWORD: ${SUPER_ADMIN_PASSWORD:?}
      APP_ENV: production
      ADMIN_ADDR: "0.0.0.0:8081"
    ports:
      - "8080:8080"
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }
    restart: unless-stopped
```

Set `JWT_AUDIENCE` to this project's name — it is what stops a token minted for
one service being accepted by another. Do **not** publish `8081`.

If the project has no Postgres or Redis, add them, with healthchecks and a named
volume for Postgres.

**Secrets.** Append to `.env`, keeping any existing values:

```bash
GOAUTH_JWT_PRIVATE_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)     # only if absent
```

Generate them by actually running `openssl`, not by inventing a string. The
database password is **hex**: base64 contains `/` and `+`, and a `/` inside a
connection URL ends the authority section, so the driver reads the rest of the
password as a hostname. If `.env` is tracked by git, stop and tell the user
before writing a key into it.

**The users table.** Add a migration in whatever tool the project already uses —
do not introduce a new one:

```sql
CREATE TABLE users (
    id          bigserial PRIMARY KEY,
    external_id uuid NOT NULL UNIQUE,   -- goauth's user id: the JWT `sub`
    created_at  timestamptz NOT NULL DEFAULT now()
);
```

No foreign key to goauth — separate databases make one impossible, and that is
deliberate. If the project already has a `users` table, add `external_id` to it
instead of creating a second one.

## 3. Tell them what to do next

```bash
docker compose up -d auth
```

The admin credentials are whatever `SUPER_ADMIN_USERNAME` and
`SUPER_ADMIN_PASSWORD` say — add both to `.env`. Nothing is generated and
nothing is printed to the log.

Then point them at `/goauth-verify` to wire token verification into the service.
