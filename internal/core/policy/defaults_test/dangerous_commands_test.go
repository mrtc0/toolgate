package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
)

// TestDangerousCommandsDefaultPolicy loads defaults:dangerous-commands with a
// default allow so scenarios assert exactly which commands the rules gate.
func TestDangerousCommandsDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:dangerous-commands
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, cmd, action, rule string
	}{
		// rm -rf
		{"rm-rf", "rm -rf /tmp/x", "ask", "ask-rm-rf"},
		{"rm-long-flags", "rm --recursive --force /tmp/x", "ask", "ask-rm-rf"},
		{"rm-combined-flags", "rm -fr /tmp/x", "ask", "ask-rm-rf"},
		{"rm-recursive-only", "rm -r /tmp/x", "allow", "default"},
		{"rm-force-only", "rm -f /tmp/x", "allow", "default"},
		{"rm-plain", "rm file.txt", "allow", "default"},

		// shell redirect file writes
		{"redirect-truncate", "echo pwned > out.txt", "ask", "ask-redirect-file-write"},
		{"redirect-append", "echo x >> log.txt", "ask", "ask-redirect-file-write"},
		{"redirect-devnull", "echo x > /dev/null", "allow", "default"},
		{"no-redirect", "echo hello", "allow", "default"},

		// sed script exec / file access
		{"sed-exec-flag", "sed 's/foo/bar/e'", "ask", "ask-sed-script-exec-or-file"},
		{"sed-write-file", "sed '1,5w output.txt'", "ask", "ask-sed-script-exec-or-file"},
		{"sed-exec-cmd", "sed 'e'", "ask", "ask-sed-script-exec-or-file"},
		{"sed-script-file", "sed -f script.sed input.txt", "ask", "ask-sed-script-exec-or-file"},
		{"sed-plain-substitute", "sed 's/foo/bar/' input.txt", "allow", "default"},

		// find/fd exec or delete
		{"find-exec", "find . -name '*.tmp' -exec rm {} ;", "ask", "ask-find-exec-or-delete"},
		{"find-delete", "find . -name '*.tmp' -delete", "ask", "ask-find-exec-or-delete"},
		{"fd-exec", "fd -e log -X rm", "ask", "ask-find-exec-or-delete"},
		{"find-plain", "find . -name '*.go'", "allow", "default"},

		{"unrelated", "ls -la", "allow", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Evaluate(enginetest.BashInput(tc.cmd), pol, engine.Options{})
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("cmd %q: got (%s, %s), want (%s, %s)", tc.cmd, d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}
