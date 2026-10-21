package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gos0001/goauth/v2/internal/adapter/redis"
	"github.com/gos0001/goauth/v2/internal/middleware"
	"github.com/gos0001/goauth/v2/internal/usecases/audit_cleaner"
	"github.com/gos0001/goauth/v2/internal/usecases/outbox_cleaner"
	"github.com/gos0001/goauth/v2/internal/usecases/session_cleaner"
	"github.com/gos0001/goauth/v2/internal/usecases/webhook_dispatcher"
	"github.com/gos0001/goauth/v2/pkg/appconfig"
	"github.com/gos0001/goauth/v2/pkg/cors"
	"github.com/gos0001/goauth/v2/pkg/ratelimit"
	"github.com/gos0001/goauth/v2/pkg/token"
	"github.com/gos0001/goauth/v2/pkg/webhook"
)

// TestConfigExampleBoots is the regression guard for the v2.0.2 duration bug:
// config.example.json writes durations as strings ("15m"), which encoding/json
// cannot unmarshal into time.Duration. The example is the contract users copy
// — it must survive Load plus every LoadConfig, with the documented values.
func TestConfigExampleBoots(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw = []byte(strings.Replace(string(raw), "REPLACE_WITH_MAKE_JWT_KEY", seed, 1))

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	root, err := appconfig.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	appCfg, err := LoadConfig(root)
	if err != nil {
		t.Fatalf("cmd LoadConfig: %v", err)
	}
	if appCfg.Addr != ":8080" || appCfg.AdminAddr != "127.0.0.1:8081" {
		t.Errorf("app = %+v", appCfg)
	}

	tokenCfg, err := token.LoadConfig(root)
	if err != nil {
		t.Fatalf("token.LoadConfig: %v", err)
	}
	if tokenCfg.AccessTTL != 15*time.Minute || tokenCfg.RefreshTTL != 720*time.Hour {
		t.Errorf("token ttls = %v / %v, want 15m / 720h", tokenCfg.AccessTTL, tokenCfg.RefreshTTL)
	}

	corsCfg, err := cors.LoadConfig(root)
	if err != nil {
		t.Fatalf("cors.LoadConfig: %v", err)
	}
	if corsCfg.MaxAge != 12*time.Hour {
		t.Errorf("cors max_age = %v, want 12h", corsCfg.MaxAge)
	}

	webhookCfg, err := webhook.LoadConfig(root)
	if err != nil {
		t.Fatalf("webhook.LoadConfig: %v", err)
	}
	if webhookCfg.Timeout != 10*time.Second {
		t.Errorf("webhook timeout = %v, want 10s", webhookCfg.Timeout)
	}

	rlCfg, err := ratelimit.LoadConfig(root)
	if err != nil {
		t.Fatalf("ratelimit.LoadConfig: %v", err)
	}
	if rlCfg.BackoffBase != time.Second || rlCfg.BackoffMax != 60*time.Second || rlCfg.FailureWindow != 15*time.Minute {
		t.Errorf("ratelimit backoff = %v / %v / %v, want 1s / 60s / 15m",
			rlCfg.BackoffBase, rlCfg.BackoffMax, rlCfg.FailureWindow)
	}

	redisCfg, err := redis.LoadConfig(root)
	if err != nil {
		t.Fatalf("redis.LoadConfig: %v", err)
	}
	if redisCfg.DefaultTTL != time.Hour {
		t.Errorf("redis default_ttl = %v, want 1h", redisCfg.DefaultTTL)
	}

	mwCfg, err := middleware.LoadConfig(root)
	if err != nil {
		t.Fatalf("middleware.LoadConfig: %v", err)
	}
	if mwCfg.ReauthWindow != 15*time.Minute {
		t.Errorf("admin reauth_window = %v, want 15m", mwCfg.ReauthWindow)
	}

	sessionCfg, err := session_cleaner.LoadConfig(root)
	if err != nil {
		t.Fatalf("session_cleaner.LoadConfig: %v", err)
	}
	if sessionCfg.Interval != time.Hour {
		t.Errorf("sessions cleanup_interval = %v, want 1h", sessionCfg.Interval)
	}

	auditCfg, err := audit_cleaner.LoadConfig(root)
	if err != nil {
		t.Fatalf("audit_cleaner.LoadConfig: %v", err)
	}
	if auditCfg.Retention != 720*time.Hour || auditCfg.Interval != 6*time.Hour {
		t.Errorf("audit retention/interval = %v / %v, want 720h / 6h", auditCfg.Retention, auditCfg.Interval)
	}

	outboxCfg, err := outbox_cleaner.LoadConfig(root)
	if err != nil {
		t.Fatalf("outbox_cleaner.LoadConfig: %v", err)
	}
	if outboxCfg.Interval != time.Hour || outboxCfg.Retention != 168*time.Hour || outboxCfg.MaxAge != 720*time.Hour {
		t.Errorf("outbox = %v / %v / %v, want 1h / 168h / 720h",
			outboxCfg.Interval, outboxCfg.Retention, outboxCfg.MaxAge)
	}

	dispatcherCfg, err := webhook_dispatcher.LoadConfig(root)
	if err != nil {
		t.Fatalf("webhook_dispatcher.LoadConfig: %v", err)
	}
	if dispatcherCfg.Interval != 10*time.Second || dispatcherCfg.Timeout != 10*time.Second ||
		dispatcherCfg.BackoffBase != 10*time.Second || dispatcherCfg.BackoffMax != time.Hour {
		t.Errorf("dispatcher = %v / %v / %v / %v, want 10s / 10s / 10s / 1h",
			dispatcherCfg.Interval, dispatcherCfg.Timeout, dispatcherCfg.BackoffBase, dispatcherCfg.BackoffMax)
	}
}
