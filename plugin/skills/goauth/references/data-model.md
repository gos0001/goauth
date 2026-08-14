# Linking your users to goauth

goauth lives in its own database, so there is no foreign key to reach for — which
is the point. Your service keeps its own user row and stores goauth's id beside
it.

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

CREATE TABLE user_roles (
    user_id bigint PRIMARY KEY REFERENCES users (id),
    role    text NOT NULL DEFAULT 'user'
);
```

Four decisions in that schema, each one commonly got wrong:

**Your primary key stays yours.** Subscriptions, roles, orders and everything
else reference `users.id`, never the auth UUID. That is what makes replacing the
auth provider later a change to one column rather than to every foreign key in
the schema.

**`external_id` is unique and never reused.** It is the `sub` claim.

**The row is created on first sighting**, not pushed by goauth. On the first
authenticated request, upsert and carry on — goauth never learns your application
exists, which is what keeps it reusable across projects.

**Deletion is two-sided.** goauth soft-deletes and clears identifiers; your row
survives, and you decide whether that means anonymise or remove.

## Upsert on first request

```go
func (r *Users) Resolve(ctx context.Context, externalID string) (int64, error) {
    var id int64
    err := r.db.QueryRow(ctx, `
        INSERT INTO users (external_id) VALUES ($1)
        ON CONFLICT (external_id) DO UPDATE SET external_id = EXCLUDED.external_id
        RETURNING id`, externalID).Scan(&id)
    return id, err
}
```

The `DO UPDATE` assigning the column to itself looks pointless but is not:
`DO NOTHING` returns no row on conflict, so a returning-upsert needs an update
that always fires.

## Where authorisation lives

goauth answers *who*. Your service answers *what they may do* — and it should
read that from its own tables on every request, not from the token.

A token lives up to its full TTL and cannot be revoked. Putting a plan or a role
in it means: a subscription that expired at 12:00 keeps working until 12:15, and
worse, a user who **pays** at 12:00 stays on the free tier until then and opens a
support ticket.

```go
sub, err := subscriptions.Get(ctx, userID)   // your database, no network call
if err != nil || !sub.Active(time.Now()) {
    // 402, not 403 — the frontend shows a paywall rather than "access denied"
    return c.AbortWithStatus(http.StatusPaymentRequired)
}
```

Store the expiry and compute the status when reading it. A boolean flipped by a
nightly job is wrong for as long as that job is late or failed:

```sql
expires_at  timestamptz,      -- compare against now() at read time
status      text NOT NULL     -- active | past_due | canceled, moved by the billing webhook
```

## Managing users from your own admin panel

goauth's `/admin/*` endpoints handle accounts: create, list, block, unblock, soft
delete, force a password, list and revoke sessions, read the audit log.

Two ways in, and they must not be confused:

- **Public port `8080`,** with a normal user JWT whose goauth account has
  `is_admin`. This is what a browser panel uses. goauth re-reads the flag from
  its database on every request, so revoking admin takes effect immediately.
- **Private port `8081`,** with the static `ADMIN_TOKEN`, for machines only — a
  payment webhook creating an account after purchase, a CI job, a script. **Never
  give this token to a browser:** it is shared, does not expire, and cannot be
  revoked for one holder.

### What the admin surface answers

| Status | Meaning | What the client does |
|---|---|---|
| `401` with `{"error":"token expired"}` | the access token is past its TTL | refresh, then retry |
| `404`, empty body | not an admin, no token, or a token this service did not issue | nothing; retrying will not help |
| `403 reauthentication required` | destructive call outside the sudo window | prompt for the password, retry |

The empty `404` is deliberate: it makes the surface indistinguishable from a
route that was never registered. Expiry is the one exception, because a client
otherwise has no way to know it should refresh.

Destructive calls (`PATCH`, `DELETE`, setting a password) additionally require
that the acting admin presented their password within `ADMIN_REAUTH_WINDOW`
(15 minutes by default). A `403 reauthentication required` means the panel should
prompt for the password and retry, not that the user lacks rights.

Creating an account after payment, from your backend:

```
POST http://auth:8081/admin/users
Authorization: Bearer $ADMIN_TOKEN
{"username": "...", "email": "...", "password": "<random>"}
```

Then store `external_id` from the response alongside the subscription, and send
the user a link to set their own password rather than mailing them the generated
one.
