package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// TestSelfProtectionDefaultPolicy loads defaults:self-protection with a default
// allow so scenarios assert exactly which writes are blocked.
func TestSelfProtectionDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:self-protection
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		{"write-toolgate-yaml", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".toolgate.yaml")},
		{"write-claude-json", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".claude.json")},
		{"write-claude-settings", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".claude/settings.json")},
		{"write-claude-settings-local", "deny", "protect-gate-config", enginetest.FileInput("Edit", "/proj", "", ".claude/settings.local.json")},
		{"write-claude-hook", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".claude/hooks/pre.sh")},
		{"write-cursor-hooks", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".cursor/hooks.json")},
		{"write-github-hook", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".github/hooks/run.sh")},
		{"write-copilot-hook", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".copilot/hooks/run.sh")},
		{"write-managed-settings", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", "/etc/claude-code/managed-settings.json")},
		{"write-config-toolgate", "deny", "protect-gate-config", enginetest.FileInput("Write", "/proj", "", ".config/toolgate/policy.yaml")},

		// Reads of the same files are not blocked (rule only guards writes).
		{"read-toolgate-yaml", "allow", "default", enginetest.FileInput("Read", "/proj", "", ".toolgate.yaml")},
		{"read-claude-settings", "allow", "default", enginetest.FileInput("Read", "/proj", "", ".claude/settings.json")},

		// Unrelated writes pass.
		{"write-source-file", "allow", "default", enginetest.FileInput("Write", "/proj", "", "main.go")},
		{"write-claude-other", "allow", "default", enginetest.FileInput("Write", "/proj", "", ".claude/memory/notes.md")},
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
