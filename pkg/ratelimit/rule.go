package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Rule is a fixed-window allowance, configured as "<count>/<duration>" —
// for example "100/15m". It implements encoding.TextUnmarshaler so it can be
// read straight from a JSON string.
type Rule struct {
	Limit  int
	Window time.Duration
}

func (r *Rule) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	if value == "" {
		return nil
	}

	limit, window, ok := strings.Cut(value, "/")
	if !ok {
		return fmt.Errorf("ratelimit: %q must look like \"100/15m\"", value)
	}

	n, err := strconv.Atoi(strings.TrimSpace(limit))
	if err != nil || n <= 0 {
		return fmt.Errorf("ratelimit: %q has an invalid count", value)
	}

	d, err := time.ParseDuration(strings.TrimSpace(window))
	if err != nil || d <= 0 {
		return fmt.Errorf("ratelimit: %q has an invalid window", value)
	}

	r.Limit, r.Window = n, d
	return nil
}

func (r Rule) String() string { return fmt.Sprintf("%d/%s", r.Limit, r.Window) }

// Enabled reports whether the rule should be enforced. A zero rule is a
// deliberately disabled one.
func (r Rule) Enabled() bool { return r.Limit > 0 && r.Window > 0 }
