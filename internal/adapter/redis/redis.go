// Package redis adapts Redis to domain types. Keys and TTLs are configured
// here, not scattered through use cases.
package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/gos0001/goauth/internal/domain"
	pkgredis "github.com/gos0001/goauth/pkg/redis"
)

type Adapter struct {
	client *pkgredis.Client
	cfg    Config
}

func New(client *pkgredis.Client, cfg Config) *Adapter {
	return &Adapter{client: client, cfg: cfg}
}

// Set stores a value under the configured key prefix.
func (a *Adapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = a.cfg.DefaultTTL
	}
	return a.client.Set(ctx, a.key(key), value, ttl).Err()
}

// Get returns domain.ErrNotFound when the key is absent, so callers branch on a
// domain error rather than on redis.Nil.
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

func (a *Adapter) Delete(ctx context.Context, key string) error {
	return a.client.Del(ctx, a.key(key)).Err()
}

func (a *Adapter) key(k string) string {
	return a.cfg.KeyPrefix + k
}
