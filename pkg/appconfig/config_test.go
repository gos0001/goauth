package appconfig

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testDurationConfig struct {
	Access time.Duration  `json:"access"`
	Ptr    *time.Duration `json:"ptr"`
	Nested struct {
		Deep time.Duration `json:"deep"`
	} `json:"nested"`
	Other string `json:"other"`
}

func loadTestSection(t *testing.T, section string) (testDurationConfig, error) {
	t.Helper()
	root := Config{sections: map[string]json.RawMessage{"s": json.RawMessage(section)}}
	cfg := testDurationConfig{Access: 5 * time.Minute} // pre-filled default
	err := root.Section("s", &cfg)
	return cfg, err
}

func TestSectionStringDurations(t *testing.T) {
	cfg, err := loadTestSection(t, `{"access":"15m","ptr":"1h30m","nested":{"deep":"10s"},"other":"x"}`)
	if err != nil {
		t.Fatalf("Section: %v", err)
	}
	if cfg.Access != 15*time.Minute {
		t.Errorf("access = %v, want 15m", cfg.Access)
	}
	if cfg.Ptr == nil || *cfg.Ptr != 90*time.Minute {
		t.Errorf("ptr = %v, want 1h30m", cfg.Ptr)
	}
	if cfg.Nested.Deep != 10*time.Second {
		t.Errorf("nested.deep = %v, want 10s", cfg.Nested.Deep)
	}
	if cfg.Other != "x" {
		t.Errorf("other = %q, want %q", cfg.Other, "x")
	}
}

func TestSectionNumberDuration(t *testing.T) {
	cfg, err := loadTestSection(t, `{"access":900000000000}`)
	if err != nil {
		t.Fatalf("Section: %v", err)
	}
	if cfg.Access != 15*time.Minute {
		t.Errorf("access = %v, want 15m", cfg.Access)
	}
}

func TestSectionNullKeepsDefault(t *testing.T) {
	cfg, err := loadTestSection(t, `{"access":null,"ptr":null}`)
	if err != nil {
		t.Fatalf("Section: %v", err)
	}
	if cfg.Access != 5*time.Minute {
		t.Errorf("access = %v, want the 5m default preserved by null", cfg.Access)
	}
	if cfg.Ptr != nil {
		t.Errorf("ptr = %v, want nil preserved by null", cfg.Ptr)
	}
}

func TestSectionAbsentKeyKeepsDefault(t *testing.T) {
	cfg, err := loadTestSection(t, `{"other":"y"}`)
	if err != nil {
		t.Fatalf("Section: %v", err)
	}
	if cfg.Access != 5*time.Minute {
		t.Errorf("access = %v, want the 5m default preserved by absence", cfg.Access)
	}
}

func TestSectionInvalidDuration(t *testing.T) {
	_, err := loadTestSection(t, `{"access":"15x"}`)
	if err == nil {
		t.Fatal("want error for invalid duration string, got nil")
	}
	if !strings.Contains(err.Error(), `config section "s": access: time: `) ||
		!strings.Contains(err.Error(), `"15x"`) {
		t.Errorf("error = %q, want it to name section, key and value", err.Error())
	}
}

func TestSectionInvalidNestedDuration(t *testing.T) {
	_, err := loadTestSection(t, `{"nested":{"deep":"x"}}`)
	if err == nil {
		t.Fatal("want error for invalid nested duration string, got nil")
	}
	if !strings.Contains(err.Error(), `deep: time: `) {
		t.Errorf("error = %q, want it to name the nested key", err.Error())
	}
}
