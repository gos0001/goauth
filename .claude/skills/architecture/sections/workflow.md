# Daily workflow

## First run

```bash
make tools                     # air, wire, sqlc, golangci-lint
make docker-up                 # dependencies via compose
cp config.example.json config.json
make jwt-key                   # paste into token.private_key
make dev
```

## Make targets

| Target | Does |
|---|---|
| `dev` | air, rebuilding on change (`-config config.json`) |
| `run` | one-shot `go run ./cmd -config config.json` |
| `build` | binary into `./bin/app` |
| `build-prod` | production build |
| `generate` | `sqlc generate`, then `wire ./cmd/` |
| `test` | `go test ./... -race -count=1` |
| `lint` | golangci-lint |
| `docker-up` / `docker-down` | compose dependencies |
| `jwt-key` / `admin-token` | `openssl rand -base64 32` for the config file |

`generate` runs sqlc first on purpose: wire cannot compile the postgres adapter
until the `generated/` package exists. Running them the other way round fails
with a confusing missing-package error.

## Configuration

One JSON file, no environment variables. `cmd` parses `-config`, `pkg/appconfig`
loads it once, and every package pulls its own section:

```go
func LoadConfig(root appconfig.Config) (Config, error) {
    cfg := Config{Timeout: 10 * time.Second} // defaults first
    if err := root.Section("webhook", &cfg); err != nil {
        return Config{}, err
    }
    if cfg.URL == "" { /* required check */ }
    return cfg, nil
}
```

Unmarshalling over pre-filled defaults means a key absent from the file leaves
the default in place. `LoadConfig` goes in that package's `wire.Set`, so wire
injects it. Validate required values explicitly — there is no `required:"true"`
tag to lean on anymore.

Several packages may read different keys from one section (`auth` is read by
three); unknown keys are ignored, so partial readers stay narrow. The example
file `config.example.json` documents every key; the local `config.json` holds
real secrets and is gitignored.

## The dev loop

air watches `.go` and `.json` (a config edit restarts the service too), and
passes `-config config.json`.

After any constructor change, re-run `wire ./cmd/`. Forgetting it produces a
build error about arguments not matching — that is wire_gen.go being stale, not
your code being wrong.

## Testing

Tests live beside the code, in the same package, so they can construct structs
directly without going through `New`:

```go
package user_get

type fakePostgres struct{ user domain.User; err error }

func (f fakePostgres) GetUserByID(context.Context, string) (domain.User, error) {
    return f.user, f.err
}

func TestExecuteReturnsNotFoundForMissingUser(t *testing.T) {
    uc := Usecase{postgres: fakePostgres{err: domain.ErrUserNotFound}}
    _, err := uc.Execute(context.Background(), Input{ID: "x"})
    if !errors.Is(err, domain.ErrUserNotFound) {
        t.Fatalf("got %v", err)
    }
}
```

Plain structs, no mocking library. One behaviour per test, named after the
behaviour — never `TestExecute1`. For use cases that go through `roleguard`,
a `fakeGuard` answering as one fixed role keeps rank tests table-driven; see
`internal/usecases/admin/admin_user_update/rank_test.go`.
