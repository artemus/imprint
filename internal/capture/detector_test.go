package capture

import "testing"

func TestExplicitFeedbackForms(t *testing.T) {
	tests := []struct{ text, marker, route string }{
		{"No, use the compact synthetic card.", "direct", "correction"},
		{"Why did you remove the neutral heading?", "question_form", "correction"},
		{"This is not landing; it feels too broad.", "indirect", "correction"},
		{"I prefer the neutral version over the ornate one.", "preference", "preference"},
		{"We must keep source references on every claim.", "standard", "standard"},
		{"Approved. Ship it.", "approval", "approval"},
		{"I reject this synthetic draft.", "rejection", "refusal"},
		{"Do not publish that synthetic example.", "refusal", "refusal"},
	}
	for _, test := range tests {
		got := Detect(test.text, "", "synthetic output")
		if !got.IsFeedback || got.Marker != test.marker || got.Route != test.route {
			t.Errorf("%q: %#v", test.text, got)
		}
	}
}

func TestPoliteFeedbackRequiresPriorOutput(t *testing.T) {
	text := "Please keep the second heading and remove the first."
	if Detect(text, "", "").IsFeedback {
		t.Fatal("captured context-free polite edit")
	}
	if got := Detect(text, "", "draft"); got.Marker != "polite" {
		t.Fatalf("got %#v", got)
	}
}

func TestSilentReask(t *testing.T) {
	text := "Create a concise neutral summary with source labels."
	got := Detect(text, "Create a concise neutral summary with source labels", "unrelated")
	if !got.IsFeedback || got.Marker != "silent_reask" {
		t.Fatalf("got %#v", got)
	}
}

func TestNegativeControls(t *testing.T) {
	values := []string{"What time is the synthetic review?", "I don't know the answer.", "I have never visited that place.", "Could you create a new summary?", "Thanks for the update.", "No idea where the fixture lives.", "We must leave for the airport by six.", "The server must restart after patching."}
	for _, value := range values {
		if got := Detect(value, "", "prior answer"); got.IsFeedback {
			t.Errorf("captured %q as %#v", value, got)
		}
	}
}
