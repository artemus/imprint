package ceremony

import (
	"strings"
	"testing"
)

func TestNativeConsoleRejectsRedirectedInputBeforeOpeningTTY(t *testing.T) {
	if err := (NativeConsole{}).RequireNative(strings.NewReader("")); err == nil || err.Error() != "redirected stdin cannot raise authority" {
		t.Fatalf("err=%v", err)
	}
}

func TestNativeConsoleRejectsHookAndNoninteractiveEnvironments(t *testing.T) {
	for _, name := range []string{"IMPRINT_HOOK", "IMPRINT_NONINTERACTIVE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "1")
			if err := (NativeConsole{}).RequireNative(strings.NewReader("")); err == nil || err.Error() != "hooks and non-interactive processes cannot raise authority" {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
