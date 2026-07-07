package engine

import (
	"os"
	"testing"
)

func TestSanitizeSession(t *testing.T) {
	cases := map[string]string{
		"abc-123_XY": "abc-123_XY",
		"a/b\\c":     "a_b_c",
		"":           "session",
	}
	for in, want := range cases {
		if got := sanitizeSession(in); got != want {
			t.Errorf("sanitizeSession(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSaveLastInputNoSessionUsesDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	SaveLastInput("claude-code", "", []byte(`{"tool_name":"Bash"}`))
	if _, err := os.Stat(LastInputPath()); err != nil {
		t.Errorf("expected default input file: %v", err)
	}
}
