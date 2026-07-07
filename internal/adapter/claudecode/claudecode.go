// Package claudecode adapts Claude Code's PreToolUse hook to the toolgate
// core.
package claudecode

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/pathnorm"
)

// Adapter implements adapter.Adapter for Claude Code.
type Adapter struct{}

func (Adapter) Name() string { return string(event.AgentClaudeCode) }

// input is the PreToolUse payload Claude Code writes to the hook's stdin.
type input struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	CWD       string         `json:"cwd"`
	SessionID string         `json:"session_id"`
}

// Parse converts a Claude Code payload into a normalized event.
func (Adapter) Parse(raw []byte) (*event.Event, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	return ToEvent(in.ToolName, in.ToolInput, in.CWD, in.SessionID), nil
}

// ToEvent maps a Claude Code tool call to a normalized event. It is exported so
// the test CLI can build events from --tool/--input flags without a full
// stdin payload.
func ToEvent(toolName string, toolInput map[string]any, cwd, sessionID string) *event.Event {
	ev := &event.Event{
		Agent:     event.AgentClaudeCode,
		Tool:      toolName,
		CWD:       cwd,
		SessionID: sessionID,
		Input:     toolInput,
	}
	switch toolName {
	case "Bash":
		ev.Kind = event.KindExec
		if toolInput != nil {
			ev.Cmd, _ = toolInput["command"].(string)
		}
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		ev.Kind = event.KindFileWrite
		ev.Paths = toolPaths(toolName, toolInput, cwd)
	case "Read":
		ev.Kind = event.KindFileRead
		ev.Paths = toolPaths(toolName, toolInput, cwd)
	case "Grep", "Glob":
		ev.Kind = event.KindFileSearch
		ev.Paths = toolPaths(toolName, toolInput, cwd)
	default:
		if server, tool, ok := parseMCPName(toolName); ok {
			ev.Kind = event.KindMCP
			ev.MCP = event.MCP{Server: server, Tool: tool}
		} else {
			ev.Kind = event.KindOther
		}
	}
	return ev
}

// parseMCPName splits Claude Code's mcp__<server>__<tool> naming.
func parseMCPName(name string) (server, tool string, ok bool) {
	if !strings.HasPrefix(name, "mcp__") {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, "mcp__")
	server, tool, found := strings.Cut(rest, "__")
	if !found || server == "" {
		return "", "", false
	}
	return server, tool, true
}

// Render writes Claude Code's PreToolUse decision JSON.
func (Adapter) Render(action, reason string) ([]byte, error) {
	type hookSpecific struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	}
	payload := struct {
		HookSpecificOutput hookSpecific `json:"hookSpecificOutput"`
	}{hookSpecific{
		HookEventName:            "PreToolUse",
		PermissionDecision:       action,
		PermissionDecisionReason: reason,
	}}
	return json.Marshal(payload)
}

// toolPaths returns the normalized absolute paths a file-oriented Claude Code
// tool touches. For Grep/Glob it resolves the search base and any static glob
// prefix so policy rules see a concrete directory.
func toolPaths(tool string, input map[string]any, cwd string) []string {
	var raw []string
	switch tool {
	case "Read", "Write", "Edit", "MultiEdit":
		raw = stringField(input, "file_path")
	case "NotebookEdit":
		raw = stringField(input, "notebook_path")
	case "Grep":
		raw = stringField(input, "path")
		if len(raw) == 0 {
			raw = []string{cwd}
		}
	case "Glob":
		base := cwd
		if p := stringField(input, "path"); len(p) > 0 {
			base = p[0]
		}
		raw = []string{base}
		if pat := stringField(input, "pattern"); len(pat) > 0 {
			if prefix := pathnorm.StaticPrefix(pat[0]); prefix != "" {
				if filepath.IsAbs(prefix) {
					raw = append(raw, prefix)
				} else {
					raw = append(raw, filepath.Join(base, prefix))
				}
			}
		}
	default:
		return nil
	}

	var out []string
	seen := map[string]bool{}
	for _, r := range raw {
		for _, p := range pathnorm.WithResolved(pathnorm.Normalize(r, cwd)) {
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func stringField(input map[string]any, key string) []string {
	if input == nil {
		return nil
	}
	if v, ok := input[key].(string); ok && strings.TrimSpace(v) != "" {
		return []string{v}
	}
	return nil
}
