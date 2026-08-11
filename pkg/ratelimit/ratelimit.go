// Package ratelimit provides Redis-backed request throttling for the login and
// registration paths.
//
// Two mechanisms, for two different jobs:
//
//   - Allow is a fixed-window counter, used per IP bucket and per IP+account
//     pair. It bounds bulk traffic.
//
//   - RegisterFailure/Backoff is exponential backoff keyed on the account, used
//     after a wrong password. It is deliberately *not* a lockout: a hard lock
//     keyed on the account is itself a weapon, letting anyone deny a known user
//     access by submitting garbage passwords. Backoff slows an attacker by
//     orders of magnitude while a legitimate user waits seconds.
//
// Zero domain imports.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	goredis "github.com/redis/go-redis/v9"

	pkgredis "github.com/gos0001/goauth/pkg/redis"
)

type Limiter struct {
	client *pkgredis.Client
	cfg    Config
}

func New(client *pkgredis.Client, cfg Config) *Limiter {
	return &Limiter{client: client, cfg: cfg}
}

type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Allow increments the counter for key and reports whether the request fits
// inside the rule. A disabled rule always allows.
func (l *Limiter) Allow(ctx context.Context, key string, rule Rule) (Result, error) {
	if !rule.Enabled() {
		return Result{Allowed: true}, nil
	}

	redisKey := l.cfg.KeyPrefix + "rl:" + key

	count, err := l.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: incr %s: %w", key, err)
	}

	// Only the first increment starts the window, so the window is fixed rather
	// than sliding forward on every request.
	if count == 1 {
		if err := l.client.Expire(ctx, redisKey, rule.Window).Err(); err != nil {
			return Result{}, fmt.Errorf("ratelimit: expire %s: %w", key, err)
		}
	}

	if count > int64(rule.Limit) {
		ttl, err := l.client.TTL(ctx, redisKey).Result()
		if err != nil || ttl < 0 {
			ttl = rule.Window
		}
		return Result{Allowed: false, RetryAfter: ttl}, nil
	}

	return Result{Allowed: true, Remaining: rule.Limit - int(count)}, nil
}

// Backoff returns how long the caller must still wait before another attempt on
// this key is accepted, or zero when it may proceed now.
func (l *Limiter) Backoff(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := l.client.TTL(ctx, l.backoffKey(key)).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("ratelimit: backoff ttl %s: %w", key, err)
	}
	if ttl <= 0 {
		return 0, nil
	}
	return ttl, nil
}

// RegisterFailure records a failed attempt and returns the delay now imposed.
// The delay doubles with each consecutive failure up to BackoffMax, and the
// counter's own lifetime is extended so a slow attacker cannot reset it by
// pausing between guesses.
func (l *Limiter) RegisterFailure(ctx context.Context, key string) (time.Duration, error) {
	countKey := l.failureKey(key)

	n, err := l.client.Incr(ctx, countKey).Result()
	if err != nil {
		return 0, fmt.Errorf("ratelimit: incr failures %s: %w", key, err)
	}
	if err := l.client.Expire(ctx, countKey, l.cfg.FailureWindow).Err(); err != nil {
		return 0, fmt.Errorf("ratelimit: expire failures %s: %w", key, err)
	}

	if n < int64(l.cfg.BackoffAfter) {
		return 0, nil
	}

	steps := n - int64(l.cfg.BackoffAfter)
	delay := time.Duration(math.Pow(2, float64(steps))) * l.cfg.BackoffBase
	if delay > l.cfg.BackoffMax || delay <= 0 {
		delay = l.cfg.BackoffMax
	}

	if err := l.client.Set(ctx, l.backoffKey(key), "1", delay).Err(); err != nil {
		return 0, fmt.Errorf("ratelimit: set backoff %s: %w", key, err)
	}

	return delay, nil
}

// Reset clears the failure history after a successful authentication.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	if err := l.client.Del(ctx, l.failureKey(key), l.backoffKey(key)).Err(); err != nil {
		return fmt.Errorf("ratelimit: reset %s: %w", key, err)
	}
	return nil
}

func (l *Limiter) Config() Config { return l.cfg }

func (l *Limiter) failureKey(key string) string { return l.cfg.KeyPrefix + "fail:" + key }
func (l *Limiter) backoffKey(key string) string { return l.cfg.KeyPrefix + "backoff:" + key }
