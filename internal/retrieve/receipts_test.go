package retrieve

import (
	"path/filepath"
	"testing"
)

func TestPreparedDeliveryIsOnceAndCommitIsIdempotent(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	response := map[string]any{"status": "delivered", "payload": "context", "budget_bytes": 100}
	cached, err := Prepare(root, "session-1", "snapshot", "", response)
	if err != nil {
		t.Fatal(err)
	}
	if cached["payload"] != "context" {
		t.Fatalf("cached=%v", cached)
	}
	committed, err := Commit(root, "session-1", "snapshot", "")
	if err != nil || !committed {
		t.Fatalf("committed=%v err=%v", committed, err)
	}
	committed, err = Commit(root, "session-1", "snapshot", "")
	if err != nil || committed {
		t.Fatalf("second=%v err=%v", committed, err)
	}
	_, delivered, err := Existing(root, "session-1", "snapshot", "")
	if err != nil || !delivered {
		t.Fatalf("delivered=%v err=%v", delivered, err)
	}
}
