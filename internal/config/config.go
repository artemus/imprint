// Package config loads and validates Imprint's portable configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	CurrentVersion = "3.1.1"
	MinHookTimeout = 1
	MaxHookTimeout = 300
)

var safeLocalID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Domain is a portable retrieval partition. Empty optional fields are valid.
type Domain struct {
	ID          string   `json:"domain_id"`
	PublicLabel string   `json:"public_label"`
	SafePaths   []string `json:"safe_paths,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	Frozen      bool     `json:"frozen,omitempty"`
}

// Config is the closed public configuration contract. Extensions are retained
// separately so unknown, unnamespaced configuration fails closed.
type Config struct {
	Version            string                     `json:"config_version"`
	OperatorSlug       string                     `json:"operator_slug"`
	NodeID             string                     `json:"node_id"`
	Compiler           bool                       `json:"compiler"`
	ContextBudgetBytes int                        `json:"context_budget_bytes"`
	AllowHigherBudget  bool                       `json:"allow_higher_budget"`
	SpoolRetentionDays int                        `json:"spool_retention_days"`
	HookTimeoutSeconds int                        `json:"hook_timeout_seconds"`
	Domains            []Domain                   `json:"domains"`
	DataRoot           string                     `json:"data_root,omitempty"`
	HooksDir           string                     `json:"hooks_dir,omitempty"`
	Extensions         map[string]json.RawMessage `json:"-"`
}

func Defaults() Config {
	timeout := 10
	if runtime.GOOS == "windows" {
		timeout = 60
	}
	return Config{
		Version: CurrentVersion, OperatorSlug: "default", NodeID: "primary",
		Compiler: true, ContextBudgetBytes: 32768, SpoolRetentionDays: 30,
		HookTimeoutSeconds: timeout, Domains: []Domain{},
		Extensions: map[string]json.RawMessage{},
	}
}

func Path() (string, error) {
	if value := os.Getenv("IMPRINT_CONFIG"); value != "" {
		return expandHome(value)
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("APPDATA")
		if base == "" {
			var err error
			base, err = os.UserHomeDir()
			if err != nil {
				return "", err
			}
		}
		return filepath.Join(base, "Imprint", "config.json"), nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "imprint", "config.json"), nil
}

func Load(path string) (Config, error) {
	value := Defaults()
	if path == "" {
		var err error
		path, err = Path()
		if err != nil {
			return Config{}, err
		}
	} else {
		var err error
		path, err = expandHome(path)
		if err != nil {
			return Config{}, err
		}
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return value, value.Validate()
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	var fields map[string]json.RawMessage
	if err := decodeStrict(raw, &fields); err != nil {
		return Config{}, fmt.Errorf("corrupt config: %s: %w", path, err)
	}
	known := map[string]func(json.RawMessage) error{
		"config_version":       func(v json.RawMessage) error { return json.Unmarshal(v, &value.Version) },
		"operator_slug":        func(v json.RawMessage) error { return json.Unmarshal(v, &value.OperatorSlug) },
		"node_id":              func(v json.RawMessage) error { return json.Unmarshal(v, &value.NodeID) },
		"compiler":             func(v json.RawMessage) error { return json.Unmarshal(v, &value.Compiler) },
		"context_budget_bytes": func(v json.RawMessage) error { return json.Unmarshal(v, &value.ContextBudgetBytes) },
		"allow_higher_budget":  func(v json.RawMessage) error { return json.Unmarshal(v, &value.AllowHigherBudget) },
		"spool_retention_days": func(v json.RawMessage) error { return json.Unmarshal(v, &value.SpoolRetentionDays) },
		"hook_timeout_seconds": func(v json.RawMessage) error { return json.Unmarshal(v, &value.HookTimeoutSeconds) },
		"domains":              func(v json.RawMessage) error { return decodeStrict(v, &value.Domains) },
		"data_root":            func(v json.RawMessage) error { return json.Unmarshal(v, &value.DataRoot) },
		"hooks_dir":            func(v json.RawMessage) error { return json.Unmarshal(v, &value.HooksDir) },
	}
	for name, rawValue := range fields {
		if decode, ok := known[name]; ok {
			if err := decode(rawValue); err != nil {
				return Config{}, fmt.Errorf("invalid %s: %w", name, err)
			}
			continue
		}
		if name == "experimental" {
			if !legacyExperimentalDisabled(rawValue) {
				return Config{}, errors.New("experimental flags were removed because no shipped runtime implemented them")
			}
			continue
		}
		if !strings.Contains(name, ".") {
			return Config{}, fmt.Errorf("unknown config key %q; namespace extensions with a dot", name)
		}
		value.Extensions[name] = rawValue
	}
	if value.Version == "3.0.0" {
		value.Version = CurrentVersion
	}
	return value, value.Validate()
}

func (c Config) Validate() error {
	if c.Version != CurrentVersion {
		return errors.New("unsupported config_version")
	}
	if !safeLocalID.MatchString(c.OperatorSlug) {
		return errors.New("operator_slug must be a safe lowercase identifier")
	}
	if !safeLocalID.MatchString(c.NodeID) {
		return errors.New("node_id must be a safe lowercase identifier")
	}
	if c.ContextBudgetBytes < 4096 || c.ContextBudgetBytes > 131072 {
		return errors.New("context_budget_bytes must be 4096..131072")
	}
	if c.ContextBudgetBytes > 32768 && !c.AllowHigherBudget {
		return errors.New("context_budget_bytes above 32768 requires allow_higher_budget=true")
	}
	if c.SpoolRetentionDays < 1 || c.SpoolRetentionDays > 36500 {
		return errors.New("spool_retention_days must be 1..36500")
	}
	if c.HookTimeoutSeconds < MinHookTimeout || c.HookTimeoutSeconds > MaxHookTimeout {
		return errors.New("hook_timeout_seconds must be 1..300")
	}
	seen := map[string]bool{}
	for _, domain := range c.Domains {
		if !safeLocalID.MatchString(domain.ID) {
			return errors.New("domain_id must be a safe lowercase identifier")
		}
		if strings.TrimSpace(domain.PublicLabel) == "" {
			return errors.New("domain public_label must be a non-empty string")
		}
		if seen[domain.ID] {
			return fmt.Errorf("duplicate domain_id %q", domain.ID)
		}
		seen[domain.ID] = true
	}
	if c.HooksDir != "" && !filepath.IsAbs(c.HooksDir) {
		return errors.New("hooks_dir must be an absolute safe path")
	}
	return nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func legacyExperimentalDisabled(raw json.RawMessage) bool {
	var values map[string]bool
	if err := json.Unmarshal(raw, &values); err != nil {
		return false
	}
	for name, enabled := range values {
		if name != "digest" && name != "profile_learning" {
			return false
		}
		if enabled {
			return false
		}
	}
	return true
}

func expandHome(value string) (string, error) {
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if value == "~" {
			return home, nil
		}
		return filepath.Join(home, value[2:]), nil
	}
	return value, nil
}
