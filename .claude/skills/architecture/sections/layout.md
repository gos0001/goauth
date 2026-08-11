# Project layout — who owns which file

Import paths below are relative to `github.com/gos0001/goauth`.

## Dependency direction

Never reversed:

```
pkg/  ←  adapter/  ←  domain/  ←  usecases/  ←  controller/
```

`pkg/` is the floor: thin wrappers over libraries, zero `internal/domain` imports.
If something in `pkg/` needs a domain type, it is an adapter, not a pkg.

## Three kinds of file

**Hand-written — yours.**
`internal/domain/*.go`, `internal/usecases/**`, `pkg/**`, `cmd/app.go`,
`cmd/config.go`, `cmd/main.go`, adapters.

**Generated — regenerate, never edit.**

| File | Owner | Regenerate with |
|---|---|---|
| `cmd/wire_gen.go` | wire | `wire ./cmd/` |
| `internal/adapter/postgres/generated/` | sqlc | `sqlc generate` |

**Assembly points — yours, with marked insertion sites.**
`cmd/wire.go` and `internal/controller/http_v1/controller.go` are the two files
every new use case has to touch. They carry marker comments saying where each
piece belongs:

```go
// codegen:imports     inside the import block
// codegen:params      inside the New(...) parameter list
// codegen:routes      in the routing body
// codegen:providers   inside wire.Build(...)
```

Insert directly above the marker and leave it in place. Nothing breaks if one is
deleted, but the files then drift into whatever order each edit happened to pick,
which is how a 30-parameter constructor becomes unreadable.

## Directory map

```
cmd/                          entrypoint; graceful shutdown lives in app.go
internal/domain/              models + sentinel errors; no tags, no imports out
internal/usecases/            business logic, one package per use case
internal/service/             shared domain services (token issuing, audit)
internal/middleware/          real IP, rate limiting, auth and admin guards
internal/controller/http_v1/  public JSON routes; routing only
internal/controller/admin_v1/ admin routes, mounted on both listeners
internal/adapter/postgres/    queries/*.sql, generated/, MapError
internal/adapter/redis/       cache storage
internal/orchestrators/       startup work that runs before the listeners open
pkg/                          logger, http_server, token, passwordhash, realip,
                              ratelimit, migrator, authclient, postgres, redis
migrations/                   NNNNNN_name.up.sql / .down.sql + embed.go
```
