// Package realip resolves the client address of an HTTP request behind proxies.
//
// The threat this exists to close: X-Forwarded-For and friends are ordinary
// request headers that anyone can set. Believing them unconditionally lets an
// attacker rotate a fake address on every request (defeating rate limiting
// entirely) or, worse, send a victim's address to burn the victim's bucket and
// lock them out.
//
// So the rule is: the peer address from RemoteAddr is the only thing that
// cannot be forged, and a header is read only when that peer is a configured
// trusted proxy.
//
// Note this deliberately does not use gin's TrustedPlatform, which returns the
// platform header before checking who sent it — spoofable whenever the origin
// accepts connections from anywhere but the edge.
//
// Zero domain imports.
package realip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Header names understood for the single-value case.
const (
	HeaderCloudflare   = "CF-Connecting-IP"
	HeaderRealIP       = "X-Real-IP"
	HeaderForwardedFor = "X-Forwarded-For"
)

type Resolver struct {
	trusted []netip.Prefix
	header  string
}

// New builds a resolver. An empty trustedProxies list means no header is ever
// read — the safe default for a service exposed directly.
func New(cfg Config) (*Resolver, error) {
	prefixes, err := parseTrusted(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}

	header := strings.TrimSpace(cfg.ClientIPHeader)
	if header != "" && len(prefixes) == 0 {
		return nil, fmt.Errorf("realip: CLIENT_IP_HEADER=%q is set but TRUSTED_PROXIES is empty; "+
			"a header without a trusted peer list is forgeable by anyone", header)
	}

	return &Resolver{trusted: prefixes, header: http.CanonicalHeaderKey(header)}, nil
}

// ClientIP returns the resolved client address, falling back to the peer
// address whenever the headers cannot be trusted or cannot be parsed.
func (r *Resolver) ClientIP(req *http.Request) netip.Addr {
	peer := peerAddr(req)

	if r.header == "" || !peer.IsValid() || !r.isTrusted(peer) {
		return peer
	}

	if r.header == http.CanonicalHeaderKey(HeaderForwardedFor) {
		if ip, ok := r.fromForwardedFor(req.Header.Get(HeaderForwardedFor)); ok {
			return ip
		}
		return peer
	}

	if ip, err := netip.ParseAddr(strings.TrimSpace(req.Header.Get(r.header))); err == nil {
		return ip.Unmap()
	}
	return peer
}

// fromForwardedFor walks the chain right to left. Proxies append on the right,
// so everything to the left may have been written by the client; the first
// untrusted hop from the right is the earliest address we can still vouch for.
// Parsing left to right instead is the classic spoofable mistake.
func (r *Resolver) fromForwardedFor(value string) (netip.Addr, bool) {
	if value == "" {
		return netip.Addr{}, false
	}

	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			// A malformed entry means the chain cannot be reasoned about past
			// this point; stop rather than guess.
			return netip.Addr{}, false
		}
		ip = ip.Unmap()
		if !r.isTrusted(ip) {
			return ip, true
		}
	}

	// Every hop was a trusted proxy — no client address in the chain.
	return netip.Addr{}, false
}

func (r *Resolver) isTrusted(ip netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func peerAddr(req *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func parseTrusted(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		switch strings.ToLower(entry) {
		case "cloudflare":
			p, err := parseCIDRs(cloudflareCIDRs)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
			continue
		case "private":
			p, err := parseCIDRs(loopbackAndPrivate)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
			continue
		}

		// A bare address is accepted as a single-host prefix.
		if !strings.Contains(entry, "/") {
			ip, err := netip.ParseAddr(entry)
			if err != nil {
				return nil, fmt.Errorf("realip: trusted proxy %q is neither an address nor a CIDR: %w", entry, err)
			}
			out = append(out, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			continue
		}

		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("realip: trusted proxy %q is not a valid CIDR: %w", entry, err)
		}
		out = append(out, prefix.Masked())
	}

	return out, nil
}

func parseCIDRs(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, c := range list {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("realip: built-in CIDR %q is invalid: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Bucket collapses an address into the unit a rate limiter should count.
//
// IPv6 clients are handed an entire prefix — commonly a /64 — so counting full
// addresses lets one client present effectively unlimited distinct keys.
func Bucket(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	if ip.Is6() && !ip.Is4In6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}
