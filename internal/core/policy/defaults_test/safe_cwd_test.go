package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// TestSafeCwdDefaultPolicy loads defaults:safe-cwd with a default ask so
// scenarios assert exactly which in-cwd activity is allowed and which
// out-of-cwd access is escalated.
func TestSafeCwdDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: ask
include:
  - defaults:safe-cwd
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		// File tools inside cwd are allowed.
		{"read-in-cwd", "allow", "allow-file-tools-in-cwd", enginetest.FileInput("Read", "/proj", "", "main.go")},
		{"write-in-cwd", "allow", "allow-file-tools-in-cwd", enginetest.FileInput("Write", "/proj", "", "sub/out.txt")},
		{"write-devnull", "allow", "allow-file-tools-in-cwd", enginetest.FileInput("Write", "/proj", "", "/dev/null")},
		{"read-in-tmp", "allow", "allow-file-tools-in-cwd", enginetest.FileInput("Read", "/proj", "", "/tmp/scratch")},

		// File tools outside cwd escalate.
		{"read-outside-cwd", "ask", "ask-read-outside-cwd", enginetest.FileInput("Read", "/proj", "", "/etc/passwd")},
		{"write-outside-cwd", "ask", "ask-write-outside-cwd", enginetest.FileInput("Write", "/proj", "", "/etc/hosts")},

		// Read-only and known filesystem commands inside cwd are allowed.
		{"cat-in-cwd", "allow", "allow-file-commands-in-cwd", enginetest.BashInput("cat main.go")},
		{"grep-in-cwd", "allow", "allow-file-commands-in-cwd", enginetest.BashInput("grep foo main.go")},
		{"ls-in-cwd", "allow", "allow-file-commands-in-cwd", enginetest.BashInput("ls -la")},
		{"echo-plain", "allow", "allow-file-commands-in-cwd", enginetest.BashInput("echo hello")},
		{"mkdir-in-cwd", "allow", "allow-file-commands-in-cwd", enginetest.BashInput("mkdir sub")},

		// Reading outside cwd via a command escalates.
		{"cat-outside-cwd", "ask", "ask-read-outside-cwd", enginetest.BashInput("cat /etc/passwd")},

		// Commands not on the safe lists fall through to the default.
		{"unknown-command", "ask", "default", enginetest.BashInput("python script.py")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Evaluate(tc.ev, pol, engine.Options{})
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("got (%s, %s), want (%s, %s)", d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}
