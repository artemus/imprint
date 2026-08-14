package paths

import (
	"path/filepath"
	"testing"

	"github.com/artemus/imprint/internal/config"
)

func TestOperatorRoot(t *testing.T) {
	value := config.Defaults()
	value.DataRoot = filepath.Join(t.TempDir(), "data")
	got, err := OperatorRoot(value)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(value.DataRoot, "default") {
		t.Fatalf("root=%q", got)
	}
}

func TestRejectsRelativeAndSyncRoots(t *testing.T) {
	for _, root := range []string{"relative", filepath.Join(t.TempDir(), "Dropbox", "imprint")} {
		value := config.Defaults()
		value.DataRoot = root
		if _, err := OperatorRoot(value); err == nil {
			t.Errorf("accepted %q", root)
		}
	}
}
