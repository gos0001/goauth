package realip

import "github.com/gos0001/goauth/pkg/appconfig"

type Config struct {
	// TrustedProxies accepts CIDRs, bare addresses, or the keywords
	// "cloudflare" and "private". Empty — the default — means no forwarding
	// header is ever believed.
	TrustedProxies []string `json:"trusted_proxies"`

	// ClientIPHeader is the header to read once the peer is trusted:
	// CF-Connecting-IP, X-Real-IP, or X-Forwarded-For. Empty disables header
	// parsing entirely.
	ClientIPHeader string `json:"client_ip_header"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{}
	if err := root.Section("realip", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
