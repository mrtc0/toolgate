package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
)

// TestInterpreterExecDefaultPolicy loads defaults:interpreter-exec with a
// default allow so scenarios assert exactly which interpreter commands the
// rules gate.
func TestInterpreterExecDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:interpreter-exec
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, cmd, action, rule string
	}{
		// inline interpreter code
		{"python-c", "python -c 'import os'", "ask", "ask-interpreter-inline-exec"},
		{"python3-c", "python3 -c 'print(1)'", "ask", "ask-interpreter-inline-exec"},
		{"node-e", "node -e 'process.exit()'", "ask", "ask-interpreter-inline-exec"},
		{"node-print", "node -p '1+1'", "ask", "ask-interpreter-inline-exec"},
		{"ruby-e", "ruby -e 'puts 1'", "ask", "ask-interpreter-inline-exec"},
		{"perl-e", "perl -e 'print 1'", "ask", "ask-interpreter-inline-exec"},
		{"php-r", "php -r 'echo 1;'", "ask", "ask-interpreter-inline-exec"},
		{"python-script-file", "python app.py", "allow", "default"},
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
