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
//
// Duration fields stay plain time.Duration yet accept strings like "15m":
// Section rewrites them to nanoseconds before unmarshalling.
package appconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"
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
	raw, err := normalizeDurations(dst, raw)
	if err != nil {
		return fmt.Errorf("config section %q: %w", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("config section %q: %w", name, err)
	}
	return nil
}

// normalizeDurations rewrites string duration values ("15m") in the raw
// section object into the integer nanoseconds encoding/json needs, for every
// key dst declares as time.Duration or *time.Duration, directly or through
// nested structs. Numbers and null pass through untouched; a key absent from
// the file keeps dst's pre-filled default. This is why config.example.json
// can write "access_ttl": "15m" while the field stays a plain time.Duration.
func normalizeDurations(dst any, raw json.RawMessage) (json.RawMessage, error) {
	for path := range durationKeys(reflect.TypeOf(dst)) {
		segments := strings.Split(path, ".")
		normalized, err := normalizePath(raw, segments)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", segments[len(segments)-1], err)
		}
		raw = normalized
	}
	return raw, nil
}

// normalizePath walks value along segments ("nested", "deep") and rewrites the
// leaf to nanoseconds when it is a JSON string naming a duration. Anything
// else at the leaf — number, null, bool — passes through untouched.
func normalizePath(value json.RawMessage, segments []string) (json.RawMessage, error) {
	if len(segments) == 0 {
		return rewriteDuration(value)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(value, &obj); err != nil || obj == nil {
		// Not a JSON object — let the unmarshal into dst produce the error.
		return value, nil
	}
	child, ok := obj[segments[0]]
	if !ok {
		return value, nil
	}
	replaced, err := normalizePath(child, segments[1:])
	if err != nil {
		return nil, err
	}
	if bytes.Equal(replaced, child) {
		return value, nil
	}
	obj[segments[0]] = replaced
	return json.Marshal(obj)
}

// rewriteDuration turns a string duration into its nanosecond number form.
// The caller is responsible for naming the key in any error.
func rewriteDuration(value json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimLeft(value, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return value, nil
	}
	var text string
	if err := json.Unmarshal(trimmed, &text); err != nil {
		return value, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return nil, err
	}
	return json.Marshal(d.Nanoseconds())
}

var durationType = reflect.TypeOf(time.Duration(0))

// durationKeys reports the JSON paths of t (a struct, or a pointer to one)
// whose fields are time.Duration or *time.Duration, directly or through
// nested structs — dotted for nested fields, flattened for embedded ones.
// Those are the paths a config file may legitimately write as "15m" strings.
func durationKeys(t reflect.Type) map[string]bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	keys := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name := f.Tag.Get("json")
		if j := strings.IndexByte(name, ','); j >= 0 {
			name = name[:j]
		}
		if name == "" && f.Anonymous {
			for k := range durationKeys(f.Type) {
				keys[k] = true
			}
			continue
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		ft := f.Type
		if ft == durationType || ft == reflect.PointerTo(durationType) {
			keys[name] = true
			continue
		}
		if ft.Kind() == reflect.Struct || (ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct) {
			for k := range durationKeys(ft) {
				keys[name+"."+k] = true
			}
		}
	}
	return keys
}
