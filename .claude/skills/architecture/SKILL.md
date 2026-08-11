---
name: architecture
description: >
  Architecture contract for goauth: one package per use case, wire for
  dependency injection, sqlc for Postgres, and a strict layering rule between
  domain, adapters and transport. ALWAYS active in this repository — read
  before adding or editing any Go file. Auto-triggers on: "usecase",
  "use case", "endpoint", "handler", "wire", "sqlc", "migration", "query",
  "adapter", "architecture", or any edit under cmd/, internal/, or pkg/.
---

# goauth

> **ALWAYS active in this repository. Never skip these rules.**
> Module: `github.com/gos0001/goauth`.
> Exception: throwaway spikes on a scratch branch — everything else follows this.

## Core Rules (always apply)

1. **One use case = one package** under `internal/usecases/[<group>/]<name>/`, with a single `Execute(ctx, in)`. No second entry point.
2. **Package names are globally unique.** wire aliases by package name, so it is `user_get`, never `get`. Two packages named `get` collide even in different directories.
3. **Copy the shape of an existing use case.** `internal/usecases/auth/auth_me/` is the smallest complete example; `auth_token` is the fullest. See `@sections/adding-a-usecase.md`.
4. **A provider set must be consumed.** wire fails with *unused provider set* if a `Set` is added to the graph with nothing asking for it. Add it when a consumer appears, not before.
5. **Wire is the only DI.** Every package with constructors exports `var Set = wire.NewSet(...)`. Re-run `wire ./cmd/` after any constructor change.
6. **Domain is pure.** `internal/domain` holds models and sentinel errors — no struct tags, no adapter imports, no transport imports.
7. **Errors flow one way.** Adapter maps storage errors to domain errors; handler maps domain errors to HTTP status with `errors.Is`. Never leak an adapter error past the adapter.
8. **Handlers respond through `pkg/http_server`.** ⛔ **NEVER call `c.JSON` directly** — the `{"data":...}` / `{"error":...}` shape is the API contract. The one exception is the JWKS endpoint, which must serve the standard document generic clients expect.
9. **Controller only routes.** Route to handler. No logic, no domain types, no adapters.
10. **`pkg/` never imports `internal/domain`,** and config lives per package via envconfig in that package's own `config.go`. No global config struct.

## Never edit by hand

- ⛔ `cmd/wire_gen.go` — regenerate with `wire ./cmd/`
- ⛔ `internal/adapter/postgres/generated/` — regenerate with `sqlc generate`

The `// codegen:imports|params|routes|providers` comments mark where new imports,
constructor parameters, routes and provider sets belong. Keep them where they
are and insert directly above them, so the files stay in a predictable shape.

## Project Layout

```
goauth/
├── cmd/                     main.go, app.go, config.go, wire.go, wire_gen.go
├── internal/
│   ├── domain/              pure models + sentinel errors
│   ├── usecases/            one package per use case, grouped by entity
│   ├── service/             shared domain services (token issuing, audit)
│   ├── middleware/          real IP, rate limit, auth and admin guards
│   ├── controller/http_v1/  public JSON API routes
│   ├── controller/admin_v1/ admin routes + the private listener
│   ├── adapter/postgres/    queries/, generated/, MapError
│   ├── adapter/redis/       cache storage
│   └── orchestrators/       startup work that runs before the listeners open
├── pkg/                     logger, http_server, token, passwordhash, realip,
│                            ratelimit, migrator, authclient, postgres, redis
├── migrations/              golang-migrate .up/.down pairs + embed.go
├── sqlc.yaml
├── docker-compose.yml, Dockerfile, Dockerfile.dev
└── Makefile
```

## Detailed Reference

Read these when working on each layer:

- Project layout + who owns which file: `@sections/layout.md`
- Use case packages, the unit of work: `@sections/usecases.md`
- Adding a use case, step by step: `@sections/adding-a-usecase.md`
- Wire DI contract: `@sections/wire.md`
- Domain models, errors, HTTP responses: `@sections/domain-errors.md`
- Daily workflow — make, env, dev loop: `@sections/workflow.md`
- Gotchas and failure modes: `@sections/gotchas.md`
- Postgres, sqlc, migrations: `@sections/postgres.md`
- Redis: `@sections/redis.md`
- Docker and compose: `@sections/docker.md`
