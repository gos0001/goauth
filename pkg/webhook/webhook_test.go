package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func sender(url string, secret string) *Sender {
	return New(Config{URL: url, Secret: secret, Timeout: 2 * time.Second})
}

func TestSendDeliversSignedPayload(t *testing.T) {
	const secret = "s3cret"
	payload := []byte(`{"user_id":"abc","event":"user.created"}`)

	var got struct {
		body      []byte
		signature string
		timestamp string
		event     string
		eventID   string
		attempt   string
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.signature = r.Header.Get(HeaderSignature)
		got.timestamp = r.Header.Get(HeaderTimestamp)
		got.event = r.Header.Get(HeaderEvent)
		got.eventID = r.Header.Get(HeaderEventID)
		got.attempt = r.Header.Get(HeaderAttempt)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := sender(srv.URL, secret).Send(context.Background(), "evt-1", "user.created", 1, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if string(got.body) != string(payload) {
		t.Errorf("body = %s, want %s", got.body, payload)
	}
	if got.event != "user.created" || got.eventID != "evt-1" || got.attempt != "1" {
		t.Errorf("headers = %+v", got)
	}

	// The receiver's side of the contract has to work with what was actually
	// sent, which is the only thing that proves the two halves agree.
	if !Verify(secret, got.timestamp, got.signature, got.body) {
		t.Fatal("the signature sent does not verify with the same secret")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	const secret = "s3cret"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := []byte(`{"user_id":"abc"}`)
	sig := "sha256=" + Sign(secret, ts, payload)

	cases := map[string]func() bool{
		"edited body":  func() bool { return Verify(secret, ts, sig, []byte(`{"user_id":"admin"}`)) },
		"wrong secret": func() bool { return Verify("other", ts, sig, payload) },
		"replayed at another time": func() bool {
			return Verify(secret, strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10), sig, payload)
		},
		"empty signature": func() bool { return Verify(secret, ts, "", payload) },
	}

	for name, accepted := range cases {
		t.Run(name, func(t *testing.T) {
			if accepted() {
				t.Fatal("verification accepted something it must reject")
			}
		})
	}

	if !Verify(secret, ts, sig, payload) {
		t.Fatal("verification rejected a genuine request")
	}
}

// The timestamp is inside the signed string precisely so a captured request
// cannot be replayed with a fresh timestamp.
func TestSignatureCoversTheTimestamp(t *testing.T) {
	payload := []byte(`{"a":1}`)
	a := Sign("secret", "1000", payload)
	b := Sign("secret", "2000", payload)
	if a == b {
		t.Fatal("the same body signs identically at different timestamps — replay is possible")
	}
}

func TestNon2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := sender(srv.URL, "").Send(context.Background(), "evt-1", "user.created", 1, []byte(`{}`))
	if err == nil {
		t.Fatal("a 500 from the receiver must be an error so the event is retried")
	}
}

func TestTimeoutIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL, Timeout: 50 * time.Millisecond})
	if err := s.Send(context.Background(), "evt-1", "user.created", 1, []byte(`{}`)); err == nil {
		t.Fatal("a receiver slower than the timeout must be an error")
	}
}

func TestUnsignedWhenNoSecret(t *testing.T) {
	var sig atomic.Value
	sig.Store("")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig.Store(r.Header.Get(HeaderSignature))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := sender(srv.URL, "").Send(context.Background(), "e", "user.created", 1, []byte(`{}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sig.Load().(string) != "" {
		t.Fatal("a signature header was sent with no secret configured")
	}
}

// The API key is an addition for gateways, never a replacement: a request must
// still carry a signature when a secret is configured.
func TestAPIKeyIsSentAlongsideTheSignature(t *testing.T) {
	var key, sig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get(HeaderAPIKey)
		sig = r.Header.Get(HeaderSignature)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL, Secret: "s3cret", APIKey: "k-123", Timeout: 2 * time.Second})
	if err := s.Send(context.Background(), "e", "user.created", 1, []byte(`{}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if key != "k-123" {
		t.Errorf("api key header = %q, want k-123", key)
	}
	if sig == "" {
		t.Error("no signature was sent — the api key must not replace it")
	}
}

func TestNoAPIKeyHeaderWhenUnset(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(HeaderAPIKey)]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := sender(srv.URL, "s").Send(context.Background(), "e", "user.created", 1, []byte(`{}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if present {
		t.Fatal("an empty api key header was sent")
	}
}

func TestEnabled(t *testing.T) {
	if New(Config{}).Enabled() {
		t.Fatal("webhooks are enabled with no URL")
	}
	if !New(Config{URL: "http://x"}).Enabled() {
		t.Fatal("webhooks are disabled with a URL set")
	}
}
