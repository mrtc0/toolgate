// Package enginetest provides helpers for tests that evaluate policy files
// through the engine, such as the engine's own scenario tests and the
// tests for the embedded default policies.
package enginetest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/core/policy"
	"github.com/mrtc0/toolgate/internal/pathnorm"
)

// LoadPolicy loads and compiles a policy from the given user/project paths,
// failing the test on any error.
func LoadPolicy(t *testing.T, userPath, projectPath string) *policy.Compiled {
	t.Helper()
	pol, err := policy.Load(userPath, projectPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pol.Compile()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// WritePolicy writes a policy file into dir and returns its path.
func WritePolicy(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// BashInput mimics the Claude Code adapter for a Bash tool call.
func BashInput(cmd string) *event.Event {
	return &event.Event{
		Agent: event.AgentClaudeCode,
		Kind:  event.KindExec,
		Tool:  "Bash",
		Cmd:   cmd,
		CWD:   "/proj",
		Input: map[string]any{"command": cmd},
	}
}

// FileInput mimics the Claude Code adapter for a file-oriented tool: it maps
// the tool to a Kind and normalizes each path relative to cwd the way the
// adapter will. Pass home ("" if irrelevant) so home-relative rules can match.
func FileInput(tool, cwd, home string, paths ...string) *event.Event {
	kind := event.KindFileRead
	switch tool {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		kind = event.KindFileWrite
	case "Grep", "Glob":
		kind = event.KindFileSearch
	}
	var norm []string
	for _, p := range paths {
		norm = append(norm, pathnorm.WithResolved(pathnorm.Normalize(p, cwd))...)
	}
	in := map[string]any{}
	if len(paths) > 0 {
		in["file_path"] = paths[0]
	}
	return &event.Event{
		Agent: event.AgentClaudeCode,
		Kind:  kind,
		Tool:  tool,
		Paths: norm,
		CWD:   cwd,
		Home:  home,
		Input: in,
	}
}

// OtherInput mimics an agent tool call that exercises no file/exec/mcp
// capability (Kind == "other"), such as Claude Code's TodoWrite.
func OtherInput(tool string) *event.Event {
	return &event.Event{
		Agent: event.AgentClaudeCode,
		Kind:  event.KindOther,
		Tool:  tool,
		CWD:   "/proj",
		Input: map[string]any{},
	}
}
