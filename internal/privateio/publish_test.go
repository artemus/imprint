package privateio

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublishNewIsPrivateAndCreateOnly(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nested", "event.json")
	if err := PublishNew(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := PublishNew(path, []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected exists, got %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "first" {
		t.Fatalf("content=%q", raw)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode=%o", info.Mode().Perm())
		}
	}
}

func TestRejectsSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege is environment-specific")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	target, _ := filepath.EvalSymlinks(t.TempDir())
	link := filepath.Join(root, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := PublishNew(filepath.Join(link, "event.json"), []byte("x")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
}
