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

	// configDir mimics a non-default XDG_CONFIG_HOME relocation: the real user
	// policy lives here, not under a literal ".config/toolgate" segment.
	const configDir = "/home/u/xdg/toolgate"
	withConfig := func(ev *event.Event) *event.Event {
		ev.ConfigDir = configDir
		return ev
	}

	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		{"write-toolgate-yaml", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".toolgate.yaml"))},
		{"write-claude-json", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".claude.json"))},
		{"write-claude-settings", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".claude/settings.json"))},
		{"write-claude-settings-local", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Edit", "/proj", "", ".claude/settings.local.json"))},
		{"write-claude-hook", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".claude/hooks/pre.sh"))},
		{"write-cursor-hooks", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".cursor/hooks.json"))},
		{"write-github-hook", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".github/hooks/run.sh"))},
		{"write-copilot-hook", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", ".copilot/hooks/run.sh"))},
		{"write-managed-settings", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", "/etc/claude-code/managed-settings.json"))},

		// The user policy and defaults overrides are protected at their real
		// (XDG-resolved) location, not via a literal ".config/toolgate" glob.
		{"write-user-policy", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", configDir+"/policy.yaml"))},
		{"write-defaults-override", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", configDir+"/defaults/self-protection.yaml"))},
		{"write-config-dir-nested", "deny", "protect-gate-config", withConfig(enginetest.FileInput("Write", "/proj", "", configDir+"/anything.yaml"))},

		// Reads of the same files are not blocked (rule only guards writes).
		{"read-toolgate-yaml", "allow", "default", withConfig(enginetest.FileInput("Read", "/proj", "", ".toolgate.yaml"))},
		{"read-claude-settings", "allow", "default", withConfig(enginetest.FileInput("Read", "/proj", "", ".claude/settings.json"))},

		// Unrelated writes pass.
		{"write-source-file", "allow", "default", withConfig(enginetest.FileInput("Write", "/proj", "", "main.go"))},
		{"write-claude-other", "allow", "default", withConfig(enginetest.FileInput("Write", "/proj", "", ".claude/memory/notes.md"))},
		// A project-local ".config/toolgate" is not toolgate's real config dir.
		{"write-unrelated-config-toolgate", "allow", "default", withConfig(enginetest.FileInput("Write", "/proj", "", ".config/toolgate/policy.yaml"))},
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
