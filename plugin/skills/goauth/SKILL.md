---
name: goauth
description: Integrate goauth, a self-hostable identity service, into this project. Use when adding authentication, login, signup, sessions, JWT verification, or an admin/user-management surface to a service that uses or could use goauth; when the project references ghcr.io/gos0001/goauth, GOAUTH_ env vars, or a JWKS endpoint; or when the user mentions goauth by name. Covers deploying the container, verifying tokens offline against JWKS, and linking your users to goauth accounts by external_id.
---

# goauth

An identity service you run as a container. It answers exactly one question:
**who is this user.** Everything else — what they may do, what they pay for —
stays in the service that owns it.

Image: `ghcr.io/gos0001/goauth:1` · Source: https://github.com/gos0001/goauth

## What it does, and what it does not

Does: stores accounts, checks passwords, manages refresh sessions, mints
Ed25519-signed access tokens, publishes the public key at
`/.well-known/jwks.json`, and exposes an admin API for managing users.

Does **not**: product roles, subscriptions, permissions, profile data, an admin
UI, email delivery, OAuth providers, MFA.

It carries one role — `is_admin` — and that governs **goauth's own** `/admin`
endpoints, nothing in your product.

## Rules that must not be broken

These are the mistakes that make goauth stop being a separate service. Follow
them even when a shortcut looks harmless:

1. **Give goauth its own database.** Not its own tables in yours — its own
   database. It creates the database and its tables on startup.
2. **Never foreign-key into `ga_users`, and never `JOIN` it.** Your service
   stores goauth's user id as a plain column. Separate databases make this
   impossible anyway, which is the point.
3. **Never put product roles, plans or permissions in goauth.** They live in the
   service that owns them, keyed by your own user id.
4. **Never send `ADMIN_TOKEN` to a browser.** It is a shared, non-expiring
   credential for machines on the private port only. A panel authenticates with
   a normal user JWT.
5. **Verify tokens offline against the JWKS.** Do not call goauth to validate a
   token on every request, and do not share a signing secret.
6. **`JWT_AUDIENCE` is per application.** Set it and check it, or a token minted
   for one of your services is accepted by another.

## Getting a token

```
POST /auth/token
{"grant_type": "password", "identifier": "alice", "password": "..."}
```

Returns an access token (JWT, ~15 min) and a refresh token (opaque, 30 days).
`identifier` is a username or an email — goauth picks the column by whether it
contains `@`.

Refresh with `{"grant_type": "refresh_token", "refresh_token": "..."}`. Refresh
tokens are **single-use**: each exchange returns a new one and invalidates the
old. Presenting a spent token destroys the whole session family, so a client must
store the new refresh token or the user is logged out.

The access token carries `sub` (the user id), `sid`, `exp`, and `adm`. Treat
`adm` as a hint for rendering only — it cannot be revoked before it expires.

Other endpoints: `GET /auth/me`, `GET /auth/sessions`, `POST /auth/password`,
`POST /auth/revoke`, `POST /auth/logout-all`, `GET /healthz`, and `/admin/*` for
user management.

## The rest

- Deploying it, environment variables, the dedicated database:
  `references/deploy.md`
- Verifying a token in Go, Node or Python: `references/verify-token.md`
- Linking your users to goauth accounts, and the admin API:
  `references/data-model.md`

## Commands

- `/goauth-add` — add goauth to this project: compose service, generated
  secrets, and the users table that references it.
- `/goauth-verify` — wire token verification into this project's service.
