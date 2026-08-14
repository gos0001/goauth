package seed_super_admin

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// Username and Password bootstrap the first admin, used exactly as given —
	// nothing is generated and nothing is printed. Leaving Username and Email
	// empty disables seeding entirely; setting one without a Password fails the
	// boot rather than creating an account nobody can sign into.
	//
	// They apply only when no admin exists yet. Afterwards the password lives in
	// the database, so a change through /auth/password survives a restart.
	Username string `envconfig:"SUPER_ADMIN_USERNAME"`
	Password string `envconfig:"SUPER_ADMIN_PASSWORD"`
	Email    string `envconfig:"SUPER_ADMIN_EMAIL"`

	MinPasswordLength int `envconfig:"AUTH_MIN_PASSWORD_LEN" default:"12"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

func (c Config) Enabled() bool { return c.Username != "" || c.Email != "" }
