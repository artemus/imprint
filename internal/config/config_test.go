package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != CurrentVersion || got.OperatorSlug != "default" || got.ContextBudgetBytes != 32768 {
		t.Fatalf("unexpected defaults: %#v", got)
	}
}

func TestLoadUpcastsLegacyAndPreservesNamespacedExtensions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"config_version":"3.0.0","operator_slug":"default","acme.feature":{"on":true}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != CurrentVersion || len(got.Extensions) != 1 {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestLoadRejectsUnknownAndUnsafeValues(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown":          `{"unknown":true}`,
		"unsafe-id":        `{"operator_slug":"../escape"}`,
		"high-budget":      `{"context_budget_bytes":65536}`,
		"duplicate-domain": `{"domains":[{"domain_id":"x","public_label":"X"},{"domain_id":"x","public_label":"Again"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadAcceptsUTF8BOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"node_id":"secondary"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "secondary" {
		t.Fatalf("node id = %q", got.NodeID)
	}
}

func TestValidateRejectsRelativeHooksDirectory(t *testing.T) {
	value := Defaults()
	value.HooksDir = "relative/hooks"
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("unexpected error: %v", err)
	}
}
