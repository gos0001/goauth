package cors

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// AllowDomains lists the origins a browser application may call from.
	// Comma-separated, and each entry is an *origin* — scheme included:
	//
	//	https://app.example.com     one exact origin
	//	https://*.example.com       any subdomain, but not example.com itself
	//	http://localhost:3000       development
	//	*                           anything
	//
	// Empty — the default — sends no CORS headers at all, so browsers block
	// cross-origin calls. Unset means off here, never permissive.
	AllowDomains []string `envconfig:"ALLOW_DOMAINS"`

	// MaxAge is how long a browser may cache the preflight answer.
	MaxAge time.Duration `envconfig:"CORS_MAX_AGE" default:"12h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, err
	}

	// Parsed at startup so a bad entry fails the boot rather than surfacing as
	// a user's login being blocked by their browser.
	if _, _, err := parse(cfg.AllowDomains); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func parse(entries []string) (rules []rule, allowAny bool, err error) {
	for _, raw := range entries {
		entry := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "/")))
		if entry == "" {
			continue
		}

		if entry == "*" {
			allowAny = true
			continue
		}

		scheme, rest, ok := strings.Cut(entry, "://")
		if !ok || (scheme != "http" && scheme != "https") {
			// A bare "example.com" is rejected rather than guessed at: http and
			// https are different origins, so assuming one would either fail
			// silently or allow more than was asked for.
			return nil, false, fmt.Errorf(
				"cors: ALLOW_DOMAINS entry %q must be a full origin such as https://app.example.com, "+
					"https://*.example.com, or *", raw)
		}

		if host, found := strings.CutPrefix(rest, "*."); found {
			if host == "" {
				return nil, false, fmt.Errorf("cors: ALLOW_DOMAINS entry %q names no domain", raw)
			}
			rules = append(rules, rule{scheme: scheme, suffix: "." + host})
			continue
		}

		if strings.Contains(rest, "*") {
			return nil, false, fmt.Errorf(
				"cors: ALLOW_DOMAINS entry %q may only use a wildcard as a leading \"*.\" label", raw)
		}

		// Reject anything carrying a path, query or fragment: an origin is
		// scheme, host and port and nothing else, and a browser never sends
		// more than that.
		u, parseErr := url.Parse(entry)
		if parseErr != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
			return nil, false, fmt.Errorf(
				"cors: ALLOW_DOMAINS entry %q must be scheme://host[:port] with no path", raw)
		}

		rules = append(rules, rule{exact: entry})
	}

	return rules, allowAny, nil
}
