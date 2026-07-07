package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// TestSensitiveFileAccessDefaultPolicy loads defaults:sensitive-file-access
// with a default allow so scenarios assert exactly which accesses are gated.
func TestSensitiveFileAccessDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:sensitive-file-access
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		{"read-dotenv", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", ".env")},
		{"read-dotenv-local", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", ".env.local")},
		{"write-dotenv-prod", "ask", "ask-env", enginetest.FileInput("Write", "/proj", "", ".env.production")},
		{"read-nested-dotenv", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", "config/.env")},
		{"cat-dotenv", "ask", "ask-env", enginetest.BashInput("cat .env")},
		{"cp-dotenv", "ask", "ask-env", enginetest.BashInput("cp .env /tmp/steal")},

		{"read-plain-file", "allow", "default", enginetest.FileInput("Read", "/proj", "", "main.go")},
		{"read-envrc", "allow", "default", enginetest.FileInput("Read", "/proj", "", ".envrc")},
		{"read-environment", "allow", "default", enginetest.FileInput("Read", "/proj", "", "environment.yaml")},
		{"unrelated-cmd", "allow", "default", enginetest.BashInput("ls -la")},
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
