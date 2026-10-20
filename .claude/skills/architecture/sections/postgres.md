# Postgres, sqlc, migrations

## Never write SQL strings in Go

Queries live in `internal/adapter/postgres/queries/*.sql` and are compiled by
sqlc into typed Go. ⛔ **Never edit `internal/adapter/postgres/generated/`** — it
is overwritten by every `sqlc generate`.

```sql
-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;
```

The annotation sets the return shape: `:one` a single row, `:many` a slice,
`:exec` nothing.

## Order of operations

sqlc validates queries against `schema/schema.sql`, not a live database, so
a query for a table with no schema cannot compile.

```
1. write the schema         schema/schema.sql (idempotent statements)
2. write the queries        internal/adapter/postgres/queries/<entity>.sql
3. regenerate               make generate     (sqlc, then wire)
```

`make generate` runs sqlc before wire deliberately: the adapter imports
`generated/`, so wire cannot compile the package until sqlc has produced it.
Running wire first fails with a confusing missing-package error.

There is no migration tool and no version table. The schema is compiled into
the binary (`schema/embed.go`) and applied at every startup, so a container
against an empty database creates its own tables. Every statement must be
idempotent: `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`. A bare
`CREATE TABLE IF NOT EXISTS` is skipped whole once the table exists, so evolving
an existing table means restating the change as an idempotent repair at the
bottom of the file (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`, constraint drops
and re-adds). In development it is usually simpler to drop the volume — the
seed rebuilds the floor from scratch.

Startup order is schema → seed roles (`ga_roles`, `ga_role_permissions`) → seed
super admin. It matters: `ga_users.role` is NOT NULL and foreign-keyed, so the
`user` role row must exist before the first account references it.

## The adapter maps errors

Two layers: `pkg/postgres` owns the pool and knows nothing about the domain;
`internal/adapter/postgres` turns rows into domain types and storage failures
into domain errors.

```go
func MapError(err error, notFound error) error {
    if errors.Is(err, pgx.ErrNoRows) {
        return notFound            // e.g. domain.ErrUserNotFound
    }
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) && pgErr.Code == "23505" {
        return domain.ErrAlreadyExists
    }
    return err
}
```

Route every repository error through it. A `pgx` or `pgconn` error must never
reach a use case — use cases branch on domain errors only, and nothing above the
adapter should import a driver package.

Repository methods return domain types, never `generated.*` structs, and convert
`pgtype` values to plain Go types on the way out.

## Wiring the generated queries

The adapter ships without the sqlc `Queries` field, so a fresh project compiles
before sqlc has ever run. Once you have generated, add it:

```go
type Adapter struct {
    pool *pkgpostgres.Pool
    q    *generated.Queries
}

func New(pool *pkgpostgres.Pool) *Adapter {
    return &Adapter{pool: pool, q: generated.New(pool.Pool)}
}
```

Then give each entity its own file — `user_repo.go`, `post_repo.go` — rather than
one growing adapter file.

## Connection

`pkg/postgres` opens a `pgxpool` and pings it at startup, so a bad `db.url`
fails immediately rather than on the first request. The pool is closed during
graceful shutdown, after the HTTP server stops accepting requests.
