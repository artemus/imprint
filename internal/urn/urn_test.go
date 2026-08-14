package urn

import (
	"strings"
	"testing"
)

func TestNewAndRequire(t *testing.T) {
	value, err := New("operator")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "urn:imprint:operator:") {
		t.Fatalf("URN=%q", value)
	}
	if err := Require(value, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := Require(value, "session"); err == nil {
		t.Fatal("accepted wrong kind")
	}
}

func TestRejectsAliasesAndNonV4(t *testing.T) {
	values := []string{
		"URN:imprint:event:9b79cf3a-f42b-4ee8-8fb1-999388393ece",
		"urn:imprint:event:9B79CF3A-f42b-4ee8-8fb1-999388393ece",
		"urn:imprint:event:9b79cf3a-f42b-1ee8-8fb1-999388393ece",
	}
	for _, value := range values {
		if err := Require(value, "event"); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
