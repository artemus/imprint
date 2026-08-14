package transcript

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNativeTranscript(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "transcript.jsonl")
	lines := []string{mustJSON(map[string]any{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": "Prior output"}}}}), mustJSON(map[string]any{"type": "user", "message": map[string]any{"content": "No, preserve the source."}})}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperatorText != "No, preserve the source." || got.PriorAssistant != "Prior output" {
		t.Fatalf("got=%#v", got)
	}
}
func TestRejectsSymlinkAndIncompleteFinalLine(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Parse(link); err == nil {
			t.Fatal("accepted symlink")
		}
	}
	incomplete := filepath.Join(root, "incomplete")
	if err := os.WriteFile(incomplete, []byte(`{"type":"user","message":{"content":"No`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(incomplete); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v", err)
	}
}
func TestHugeTranscriptUsesBoundedTail(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "huge.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("\n" + mustJSON(map[string]any{"type": "assistant", "message": map[string]any{"content": "Prior"}}) + "\n" + mustJSON(map[string]any{"type": "user", "message": map[string]any{"content": "No, keep the bounded correction."}}) + "\n")
	if _, err = file.Seek(MaxBytes+1024-int64(len(payload)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(payload); err != nil {
		t.Fatal(err)
	}
	file.Close()
	got, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperatorText != "No, keep the bounded correction." || got.Degradation["receipt"] != "huge_transcript_bounded_tail" {
		t.Fatalf("got=%#v", got)
	}
}
func mustJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }
