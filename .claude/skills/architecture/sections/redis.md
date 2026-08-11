# Redis

Two layers, same split as Postgres.

## pkg/redis — the connection

A thin wrapper over go-redis with zero domain imports. Parses `REDIS_URL`,
connects, pings at startup so a bad URL fails immediately, and exposes `Close`
for graceful shutdown.

## internal/adapter/redis — the domain-facing side

Owns key prefixes and TTLs, and translates misses into domain errors:

```go
func (a *Adapter) Get(ctx context.Context, key string) (string, error) {
    v, err := a.client.Get(ctx, a.key(key)).Result()
    if errors.Is(err, goredis.Nil) {
        return "", domain.ErrNotFound
    }
    if err != nil {
        return "", fmt.Errorf("redis get %s: %w", key, err)
    }
    return v, nil
}
```

`goredis.Nil` never escapes the adapter — use cases branch on `domain.ErrNotFound`
like they would for any other store, and stay unaware of which one they are
talking to.

Keys are namespaced through `a.key(...)` using the configured prefix, so a shared
Redis instance does not collide across services. Do not build key strings in a
use case.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | required | e.g. `redis://localhost:6379` |
| `REDIS_KEY_PREFIX` | `goauth:` | namespace for every key |
| `REDIS_DEFAULT_TTL` | `1h` | used when `Set` is called with a zero TTL |

## Use in middleware

Middleware runs on every request, so prefer stateless checks. If a Redis lookup
is genuinely unavoidable, always wrap it in `context.WithTimeout` — a few hundred
milliseconds — and reject with 401 or 403 on timeout. Never let a request through
with degraded data because the cache was slow.
