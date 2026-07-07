package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// TestAllowClaudeCodeDefaultPolicy loads defaults:allow-claude-code with a
// default ask so scenarios assert exactly which activity the rules allow.
func TestAllowClaudeCodeDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: ask
include:
  - defaults:allow-claude-code
`)
	pol := enginetest.LoadPolicy(t, path, "")

	const home = "/home/alice"
	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		// Access inside ~/.claude is allowed.
		{"read-claude-dir", "allow", "allow-claude-dir-access", enginetest.FileInput("Read", "/proj", home, home+"/.claude/plan.md")},
		{"write-claude-memory", "allow", "allow-claude-dir-access", enginetest.FileInput("Write", "/proj", home, home+"/.claude/memory/notes.md")},

		// Access outside ~/.claude falls through to the default.
		{"read-outside-claude", "ask", "default", enginetest.FileInput("Read", "/proj", home, home+"/.ssh/id_rsa")},
		{"read-project-file", "ask", "default", enginetest.FileInput("Read", "/proj", home, "main.go")},

		// Harmless side-effect-free tools are allowed.
		{"todo-write", "allow", "allow-claude-harmless-tools", enginetest.OtherInput("TodoWrite")},
		{"ask-user-question", "allow", "allow-claude-harmless-tools", enginetest.OtherInput("AskUserQuestion")},
		{"exit-plan-mode", "allow", "allow-claude-harmless-tools", enginetest.OtherInput("ExitPlanMode")},
		{"tool-search", "allow", "allow-claude-harmless-tools", enginetest.OtherInput("ToolSearch")},

		// An unknown "other" tool is not allowlisted.
		{"unknown-other-tool", "ask", "default", enginetest.OtherInput("SomeUnknownTool")},
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
