package canonical

import (
	"testing"
)

func TestJSONSortsKeysAndPreservesUTF8(t *testing.T) {
	got, err := JSON(map[string]any{"z": "<é>", "a": map[string]any{"y": 2, "x": 1}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"x":1,"y":2},"z":"<é>"}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
