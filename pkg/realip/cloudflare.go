package realip

// cloudflareCIDRs is Cloudflare's published edge range list, expanded from the
// TRUSTED_PROXIES keyword "cloudflare". Compiled in rather than fetched so the
// service boots with no network dependency.
//
// The list changes rarely; refresh from https://www.cloudflare.com/ips-v4 and
// https://www.cloudflare.com/ips-v6 when Cloudflare announces a change. A stale
// entry fails safe: an unlisted edge address is simply not trusted, so the
// resolver falls back to the peer address instead of believing a header.
var cloudflareCIDRs = []string{
	// IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",

	// IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// loopbackAndPrivate covers the usual reverse-proxy placements: nginx on the
// same host, or an ingress inside a private network.
var loopbackAndPrivate = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}
