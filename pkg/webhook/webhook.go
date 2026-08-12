// Package webhook delivers signed event payloads to a configured URL.
//
// Signing is not optional decoration. A receiver otherwise has no way to tell an
// event from goauth apart from a POST by anyone who learned the URL — and
// webhook URLs leak: into logs, into screenshots, into the browser history of
// whoever tested it once.
//
// Zero domain imports; the caller hands over bytes.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Headers a receiver reads.
const (
	HeaderSignature = "X-Goauth-Signature" // sha256=<hex hmac of "<timestamp>.<body>">
	HeaderTimestamp = "X-Goauth-Timestamp" // unix seconds
	HeaderEvent     = "X-Goauth-Event"     // e.g. user.created
	HeaderEventID   = "X-Goauth-Event-Id"  // stable across retries
	HeaderAttempt   = "X-Goauth-Attempt"   // 1-based
	HeaderAPIKey    = "X-Goauth-Api-Key"   // optional, for gateway filtering
)

type Sender struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Sender {
	return &Sender{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Enabled reports whether a destination is configured at all.
func (s *Sender) Enabled() bool { return s.cfg.Enabled() }

// Send posts one event. A non-2xx response is an error, so the caller retries.
func (s *Sender) Send(ctx context.Context, eventID, event string, attempt int, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "goauth-webhook/1")
	req.Header.Set(HeaderEvent, event)
	req.Header.Set(HeaderEventID, eventID)
	req.Header.Set(HeaderAttempt, strconv.Itoa(attempt))
	req.Header.Set(HeaderTimestamp, timestamp)

	if s.cfg.Secret != "" {
		req.Header.Set(HeaderSignature, "sha256="+Sign(s.cfg.Secret, timestamp, payload))
	}
	if s.cfg.APIKey != "" {
		req.Header.Set(HeaderAPIKey, s.cfg.APIKey)
	}

	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	// Drain a bounded amount so the connection can be reused, and keep a little
	// of it for the error message — a receiver's 400 usually explains itself.
	body, _ := io.ReadAll(io.LimitReader(res.Body, 512))

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("webhook: %s responded %s: %s", s.cfg.URL, res.Status, bytes.TrimSpace(body))
	}

	return nil
}

// Sign computes the signature over "<timestamp>.<body>".
//
// The timestamp is inside the signed string on purpose: signing the body alone
// would let anyone who captured one request replay it forever, since the
// signature would stay valid. A receiver rejects timestamps outside a few
// minutes and the replay dies with them.
func Sign(secret, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify is what a receiver runs. Exported so consumers can copy it rather than
// reimplement the comparison — and it uses a constant-time compare, which a
// hand-rolled `==` would not.
func Verify(secret, timestamp, signature string, payload []byte) bool {
	expected := "sha256=" + Sign(secret, timestamp, payload)
	return hmac.Equal([]byte(signature), []byte(expected))
}
