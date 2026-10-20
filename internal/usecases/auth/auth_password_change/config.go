package auth_password_change

import "github.com/gos0001/goauth/v2/pkg/appconfig"

type Config struct {
	MinPasswordLength int `json:"min_password_len"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{MinPasswordLength: 12}
	if err := root.Section("auth", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
