---
description: Wire goauth token verification into this project's service, in whatever language it is written in
---

Add goauth token verification to **this** project's HTTP service. Read the
`goauth` skill and its `references/verify-token.md` first; this command applies
them.

## 1. Work out what you are adding it to

Detect from the repository, do not ask what you can read:

- The language and HTTP framework — `go.mod` and gin/chi/echo, `package.json` and
  express/fastify/hono, `pyproject.toml` and fastapi/django/flask.
- Where middleware is registered, and how existing middleware in this project is
  written. Match that shape rather than importing a new style.
- Is verification already present? If so, report it and stop.
- The JWKS URL: `http://auth:8080/.well-known/jwks.json` inside compose, or
  whatever host goauth actually runs on.
- `JWT_AUDIENCE` as configured on the goauth service — the verifier must check
  the same value.

## 2. Write it

**Go** — use the library, do not hand-roll it:

```go
import "github.com/gos0001/goauth/pkg/authclient"

mw, err := authclient.New(authclient.Config{
    JWKSURL:  os.Getenv("GOAUTH_JWKS_URL"),
    Issuer:   "goauth",
    Audience: os.Getenv("GOAUTH_AUDIENCE"),
})
r.Use(mw.Require())
```

Run `go get github.com/gos0001/goauth` and use `authclient.UserID(c)` in
handlers.

**Node** — `jose`, with `createRemoteJWKSet` created **once at module scope**; a
new one per request refetches the key set every time.

**Python** — `joserfc` or `PyJWT` with `PyJWKClient`, key set fetched once.

Whatever the language, the verifier must:

- check signature, `iss`, `aud` and `exp` — all four, every request;
- restrict the algorithm to `EdDSA`, never accept whatever the token claims;
- cache the key set and refetch on an unknown `kid`, which is how rotation works;
- verify **offline** — no call to goauth per request.

Add the configuration to `.env` and to the compose service:

```
GOAUTH_JWKS_URL=http://auth:8080/.well-known/jwks.json
GOAUTH_AUDIENCE=<this project's name>
```

## 3. Resolve the local user

Verification yields `sub`, goauth's user id. If this project has a `users` table
with `external_id`, resolve it to the local row on each authenticated request —
upsert on first sighting — and put **your** user id in the request context.
Handlers should work with the local id, so that the rest of the schema never
references the auth provider directly.

If there is no such table, say so and point at `/goauth-add`.

## 4. Do not

- Do not read roles, plans or permissions from the token. `adm` is goauth's own
  admin flag and a rendering hint at best; it cannot be revoked before the token
  expires. Read authorisation from this project's own tables.
- Do not call goauth to validate a token.
- Do not put `ADMIN_TOKEN` anywhere near this code — it belongs to server-side
  machine calls on the private port only.

## 5. Check it

Show the user how to confirm it works end to end:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","identifier":"superadmin","password":"..."}' \
  | jq -r .data.access_token)

curl -i -H "Authorization: Bearer $TOKEN" http://localhost:<this service>/<a protected route>
```

A request with no token must answer `401`, and one with a token minted for a
different `aud` must also answer `401` — that second check is the one people skip
and it is what keeps your services apart.
