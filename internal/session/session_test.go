package session

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpaqueURNIsStableAndDoesNotPersistNativeID(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	first, err := OpaqueURN(root, "provider-secret-session")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpaqueURN(root, "provider-secret-session")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "urn:imprint:session:") {
		t.Fatalf("first=%q second=%q", first, second)
	}
	other, _ := OpaqueURN(root, "other")
	if other == first {
		t.Fatal("distinct sessions collided")
	}
}
