package realip

import (
	"net/http"
	"net/netip"
	"testing"
)

func request(remoteAddr string, headers map[string]string) *http.Request {
	req := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func mustResolver(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	return r
}

// The core guarantee: a header from an untrusted peer is worthless, because
// anyone can set it. Believing it would let an attacker rotate a fake address
// per request and evade rate limiting entirely.
func TestUntrustedPeerIgnoresHeaders(t *testing.T) {
	r := mustResolver(t, Config{})

	req := request("203.0.113.9:1234", map[string]string{
		"X-Forwarded-For":  "1.2.3.4",
		"CF-Connecting-IP": "5.6.7.8",
		"X-Real-IP":        "9.9.9.9",
	})

	if got := r.ClientIP(req).String(); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %s, want the peer address 203.0.113.9", got)
	}
}

func TestHeaderWithoutTrustedProxiesIsRejectedAtStartup(t *testing.T) {
	_, err := New(Config{ClientIPHeader: "X-Forwarded-For"})
	if err == nil {
		t.Fatal("configuring a client IP header with no trusted proxies should fail loudly")
	}
}

func TestTrustedPeerReadsSingleValueHeader(t *testing.T) {
	r := mustResolver(t, Config{
		TrustedProxies: []string{"10.0.0.0/8"},
		ClientIPHeader: HeaderCloudflare,
	})

	req := request("10.1.2.3:9999", map[string]string{"CF-Connecting-IP": "198.51.100.7"})

	if got := r.ClientIP(req).String(); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %s, want 198.51.100.7", got)
	}
}

// A client may prepend anything to X-Forwarded-For; only the hops appended by
// trusted proxies, reading from the right, can be believed.
func TestForwardedForIgnoresClientSuppliedPrefix(t *testing.T) {
	r := mustResolver(t, Config{
		TrustedProxies: []string{"10.0.0.0/8"},
		ClientIPHeader: HeaderForwardedFor,
	})

	req := request("10.0.0.1:9999", map[string]string{
		// "1.1.1.1" is what the attacker wrote; "198.51.100.7" is what the
		// trusted proxy actually observed.
		"X-Forwarded-For": "1.1.1.1, 198.51.100.7, 10.0.0.5",
	})

	if got := r.ClientIP(req).String(); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %s, want 198.51.100.7 (right-most untrusted hop)", got)
	}
}

func TestForwardedForAllTrustedFallsBackToPeer(t *testing.T) {
	r := mustResolver(t, Config{
		TrustedProxies: []string{"10.0.0.0/8"},
		ClientIPHeader: HeaderForwardedFor,
	})

	req := request("10.0.0.1:9999", map[string]string{"X-Forwarded-For": "10.0.0.4, 10.0.0.5"})

	if got := r.ClientIP(req).String(); got != "10.0.0.1" {
		t.Fatalf("ClientIP = %s, want the peer 10.0.0.1", got)
	}
}

func TestForwardedForGarbageFallsBackToPeer(t *testing.T) {
	r := mustResolver(t, Config{
		TrustedProxies: []string{"10.0.0.0/8"},
		ClientIPHeader: HeaderForwardedFor,
	})

	req := request("10.0.0.1:9999", map[string]string{"X-Forwarded-For": "not-an-ip"})

	if got := r.ClientIP(req).String(); got != "10.0.0.1" {
		t.Fatalf("ClientIP = %s, want the peer 10.0.0.1", got)
	}
}

func TestCloudflareKeywordExpands(t *testing.T) {
	r := mustResolver(t, Config{
		TrustedProxies: []string{"cloudflare"},
		ClientIPHeader: HeaderCloudflare,
	})

	// 172.64.0.0/13 is one of Cloudflare's published ranges.
	req := request("172.64.0.1:443", map[string]string{"CF-Connecting-IP": "198.51.100.7"})
	if got := r.ClientIP(req).String(); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %s, want 198.51.100.7", got)
	}

	// Someone bypassing the edge is not trusted, so their spoofed header is
	// ignored and they are rate-limited under their real address.
	direct := request("203.0.113.9:443", map[string]string{"CF-Connecting-IP": "198.51.100.7"})
	if got := r.ClientIP(direct).String(); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %s, want the direct peer 203.0.113.9", got)
	}
}

// An IPv6 client owns a whole prefix, so counting full addresses would let one
// client present effectively unlimited rate-limit keys.
func TestBucketCollapsesIPv6ToSlash64(t *testing.T) {
	a := netip.MustParseAddr("2001:db8:1:2::1")
	b := netip.MustParseAddr("2001:db8:1:2:ffff:ffff:ffff:ffff")

	if Bucket(a) != Bucket(b) {
		t.Fatalf("addresses in the same /64 landed in different buckets: %s vs %s", Bucket(a), Bucket(b))
	}

	c := netip.MustParseAddr("2001:db8:1:3::1")
	if Bucket(a) == Bucket(c) {
		t.Fatal("addresses in different /64s landed in the same bucket")
	}
}

func TestBucketKeepsIPv4Exact(t *testing.T) {
	if got := Bucket(netip.MustParseAddr("198.51.100.7")); got != "198.51.100.7" {
		t.Fatalf("Bucket = %s, want the exact address", got)
	}
}
