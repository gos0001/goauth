# Verifying a goauth token

Tokens are JWTs signed with **Ed25519** (`alg: EdDSA`). goauth publishes the
public key at `/.well-known/jwks.json`, so verification happens **in your
service, offline** — no call back to goauth per request, and goauth being down
does not invalidate tokens already issued.

Always check, in this order: the signature, `iss`, `aud`, and `exp`. Skipping
`aud` is the common mistake — it is what stops a token minted for one of your
services being accepted by another.

Select the key by the token header's `kid`. On an unknown `kid`, refetch the JWKS
once: that is how key rotation works without coordinating a deploy.

## Go

```go
import "github.com/gos0001/goauth/pkg/authclient"

mw, err := authclient.New(authclient.Config{
    JWKSURL:  "http://auth:8080/.well-known/jwks.json",
    Issuer:   "goauth",
    Audience: "my-app",
})
if err != nil {
    return err
}

r.Use(mw.Require())

// in a handler
userID := authclient.UserID(c)          // the `sub` claim
claims, ok := authclient.FromContext(c) // sub, sid, jti, admin, expiry
```

`mw.Optional()` attaches claims when a valid token is present and lets the
request through otherwise, for endpoints that serve both.

The package caches the key set, refetches on an unknown `kid`, and throttles that
refetch so a flood of forged tokens cannot be turned into a flood of requests to
goauth.

## Node

```js
import { createRemoteJWKSet, jwtVerify } from 'jose'

const jwks = createRemoteJWKSet(new URL('http://auth:8080/.well-known/jwks.json'))

export async function verify(token) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: 'goauth',
    audience: 'my-app',
    algorithms: ['EdDSA'],
  })
  return payload            // payload.sub is the user id
}
```

`createRemoteJWKSet` caches and handles rotation. Create it **once at module
scope** — a new one per request refetches the key set every time.

## Python

```python
from joserfc import jwt
from joserfc.jwk import KeySet
import httpx

_jwks = KeySet.import_key_set(
    httpx.get("http://auth:8080/.well-known/jwks.json").json()
)

def verify(token: str) -> dict:
    obj = jwt.decode(token, _jwks, algorithms=["EdDSA"])
    jwt.JWTClaimsRegistry(
        iss={"essential": True, "value": "goauth"},
        aud={"essential": True, "value": "my-app"},
        exp={"essential": True},
    ).validate(obj.claims)
    return obj.claims       # claims["sub"] is the user id
```

Fetching the key set at import means rotation needs a restart; refetch on an
unknown `kid` if that matters.

`PyJWT` also works via `PyJWKClient`, but needs `cryptography` installed for
Ed25519.

## Claims

| Claim | Meaning |
|---|---|
| `sub` | the user id — this is what you store as `external_id` |
| `sid` | the session that minted the token |
| `jti` | unique token id |
| `adm` | goauth's own admin flag |
| `iss` / `aud` / `exp` / `iat` / `nbf` | standard, all verified |
| `auth_time` | when the password was last presented |

**`adm` is a rendering hint, not an authorisation decision.** A token lives up to
its full TTL and cannot be revoked, so a demoted admin still carries `adm: true`
until it expires. goauth's own admin endpoints re-read the flag from its database
on every request; anything of yours that matters should check your own data too.

## Handling failures

| Situation | Response |
|---|---|
| no or malformed token | `401` |
| expired | `401`, and the client should refresh |
| wrong `aud` or `iss` | `401` — a token for something else |
| valid token, no rights in **your** service | `403` |
| valid token, no subscription | `402`, so the frontend can show a paywall |
