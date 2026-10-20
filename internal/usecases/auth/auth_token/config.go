package auth_token

import "github.com/gos0001/goauth/pkg/appconfig"

type Config struct {
	// FailClosed makes an unreachable Redis reject login attempts rather than
	// wave them through. A cache outage must not silently open a brute-force
	// window on the one endpoint that checks passwords.
	FailClosed bool `json:"fail_closed"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{FailClosed: true}
	if err := root.Section("ratelimit", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
