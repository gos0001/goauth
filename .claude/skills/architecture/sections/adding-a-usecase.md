# Adding a use case

Every use case in this project has the same shape, so the fastest correct way to
add one is to copy the nearest existing package and change it. Two good models:

- `internal/usecases/auth/auth_me/` — the smallest complete one: a use case, a
  handler, a wire set.
- `internal/usecases/auth/auth_token/` — the fullest: config, several adapter
  interfaces, branching logic, a hand-written `Validate`.

## 1. Pick the directory and package name

```
internal/usecases/<group>/<name>/
```

The group is a directory only. The **package name must be unique across the whole
project**, because wire aliases packages by name — two packages called `get`
collide even in different directories. That is why the convention is `user_get`,
never `get`.

## 2. Write the files

```
internal/usecases/users/user_get/
├── usecase.go   Usecase struct, adapter interfaces, New, Execute
├── dto.go       Input, Output, Validate            (may live in usecase.go if small)
├── config.go    envconfig struct + LoadConfig      (only if it needs config)
├── http_v1.go   the JSON handler                   (only if an HTTP caller exists)
└── wire.go      var Set = wire.NewSet(...)
```

`usecase.go` declares the adapter interface it needs, listing **only the methods
this use case calls**, while `New` takes the *concrete* adapter — wire resolves
concrete types, not interfaces:

```go
type Postgres interface {
    GetUserByID(ctx context.Context, id string) (domain.User, error)
}

type Usecase struct {
    postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
    return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) { … }
```

`wire.go` lists the constructors the package actually has:

```go
var Set = wire.NewSet(LoadConfig, New, NewHTTPv1)   // drop LoadConfig if there is no config.go
```

## 3. Register it

Both files carry `// codegen:` comments marking where each piece goes. Insert
directly above them so the files keep a predictable shape.

**`cmd/wire.go`** — add the import and the `Set` inside `wire.Build`.

**`internal/controller/http_v1/controller.go`** — add the import, add the handler
to the `New(...)` parameter list, and register the route in the body. Admin
endpoints go through `internal/controller/admin_v1/handlers.go` instead, which
mounts the same handlers on both listeners.

Then regenerate:

```
wire ./cmd/          # or make generate, which runs sqlc first
```

Adding the `Set` and registering the route belong to the same change: wire fails
with *unused provider set* if a `Set` is reachable but nothing consumes it.

## 4. If it touches the database

Order matters, because sqlc validates queries against the migrations rather than
a live database:

```
1. migrations/NNNNNN_name.{up,down}.sql
2. make migrate-up
3. internal/adapter/postgres/queries/<entity>.sql
4. make generate           # sqlc, then wire
5. a repository method in internal/adapter/postgres/<entity>_repo.go
```

The repository method returns domain types and routes its error through
`MapError`, so the use case only ever sees domain errors.

## 5. Test it

A plain struct in the same package implementing the use case's own adapter
interface — no mocking library. Construct `Usecase{}` directly with those fakes;
the fields are unexported but the test is in the same package.
`internal/usecases/auth/auth_token/usecase_test.go` is the reference.
