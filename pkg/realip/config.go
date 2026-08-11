package realip

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// TrustedProxies accepts CIDRs, bare addresses, or the keywords
	// "cloudflare" and "private". Empty — the default — means no forwarding
	// header is ever believed.
	TrustedProxies []string `envconfig:"TRUSTED_PROXIES"`

	// ClientIPHeader is the header to read once the peer is trusted:
	// CF-Connecting-IP, X-Real-IP, or X-Forwarded-For. Empty disables header
	// parsing entirely.
	ClientIPHeader string `envconfig:"CLIENT_IP_HEADER"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
