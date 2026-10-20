// Package appconfig loads goauth's single JSON configuration file.
//
// The whole service is configured from one config.json — there are no
// environment variables. cmd parses the -config flag, calls Load once, and
// the result is passed through the wire graph. Every package keeps its own
// Config struct with json tags and pulls its section out with Section:
//
//	cfg := Config{Timeout: time.Minute} // defaults first
//	if err := root.Section("webhook", &cfg); err != nil { ... }
//
// Unmarshalling over pre-filled defaults means a key absent from the file
// leaves the default in place, exactly like envconfig's default: tag did.
package appconfig

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the parsed configuration file. It carries the top-level env
// value and the raw sections; each package decodes its own section into its
// own struct, so this package never learns what any section contains.
type Config struct {
	// Env is "development" or "production"; it picks the logger's shape.
	Env string `json:"env"`

	sections map[string]json.RawMessage
}

// Load reads and validates the configuration file at path.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var file struct {
		Env      string                     `json:"env"`
		Sections map[string]json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Everything besides "env" is a section owned by some package. Walk the
	// raw object once to keep that mapping mechanical.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	delete(top, "env")

	cfg := Config{
		Env:      file.Env,
		sections: top,
	}
	if cfg.Env == "" {
		cfg.Env = "development"
	}
	return cfg, nil
}

// Section decodes the named section into dst, which must be a pointer to a
// struct pre-filled with that package's defaults. A section missing from
// the file leaves dst untouched. Several packages may read overlapping keys
// from one section, so unknown keys are ignored rather than rejected —
// required values are validated by the package that owns them instead.
func (c Config) Section(name string, dst any) error {
	raw, ok := c.sections[name]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("config section %q: %w", name, err)
	}
	return nil
}
