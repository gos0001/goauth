package seed_super_admin

import "github.com/gos0001/goauth/v2/pkg/appconfig"

type Config struct {
	// Username and Password bootstrap the first admin, used exactly as given —
	// nothing is generated and nothing is printed. Leaving Username and Email
	// empty disables seeding entirely; setting one without a Password fails the
	// boot rather than creating an account nobody can sign into.
	//
	// They apply only when no admin exists yet. Afterwards the password lives in
	// the database, so a change through /auth/password survives a restart.
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`

	MinPasswordLength int `json:"-"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{MinPasswordLength: 12}
	if err := root.Section("seed", &cfg); err != nil {
		return Config{}, err
	}

	// The password floor is the auth section's, not a second knob: one policy,
	// one place.
	var auth struct {
		MinPasswordLength int `json:"min_password_len"`
	}
	auth.MinPasswordLength = cfg.MinPasswordLength
	if err := root.Section("auth", &auth); err != nil {
		return Config{}, err
	}
	cfg.MinPasswordLength = auth.MinPasswordLength
	return cfg, nil
}

func (c Config) Enabled() bool { return c.Username != "" || c.Email != "" }
