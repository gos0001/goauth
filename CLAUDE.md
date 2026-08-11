# goauth

Identity service in Go. Module `github.com/gos0001/goauth`.

> Read `.claude/skills/architecture/SKILL.md` before writing any Go in this
> repository. It carries the full architecture contract; this file is only the
> hard edges.

## Never edit by hand

- ⛔ `cmd/wire_gen.go` — regenerate with `wire ./cmd/` (or `make generate`)
- ⛔ `internal/adapter/postgres/generated/` — owned by `sqlc generate`

The `// codegen:imports`, `:params`, `:routes`, `:providers` comments in
`cmd/wire.go` and `internal/controller/http_v1/controller.go` mark where a new
use case's import, constructor parameter, route and provider set belong. Insert
above them and leave them in place, so those files keep a predictable order.

## Always

- One use case is one package under `internal/usecases/`, with a single
  `Execute(ctx, in)`. Copy the shape of `internal/usecases/auth/auth_me/`.
- Package names are globally unique — wire aliases by package name, so it is
  `user_get`, never `get`.
- After any constructor change, re-run `wire ./cmd/`.
- After editing `internal/adapter/postgres/queries/*.sql`, run `sqlc generate`
  **before** `wire` — wire cannot compile the adapter until `generated/` exists.
  `make generate` does both in the right order.
- Handlers respond through `pkg/http_server` helpers, never `c.JSON` directly.
  The `{"data":...}` / `{"error":...}` envelope is the API contract. The single
  exception is the JWKS endpoint, which must serve the standard document that
  generic clients expect.
- `internal/domain` imports nothing from adapters or transport, and carries no
  struct tags. Adapters map storage errors onto domain errors; handlers map
  domain errors onto HTTP status codes with `errors.Is`.
- `pkg/` never imports `internal/domain`. If it needs to, it is an adapter.
- Authorization stays out of this service. `is_admin` governs goauth's own
  `/admin` endpoints and nothing else — product roles, subscriptions and
  permissions belong to the services that own them.

## Commands

```
make dev        # air hot reload
make generate   # sqlc then wire
make test       # go test ./... -race
make lint       # golangci-lint
make docker-up  # postgres redis
make migrate-up # apply migrations by hand (the service also does it at startup)
make image      # build the container image locally
```
