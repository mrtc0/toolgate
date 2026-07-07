// Package copilot adapts GitHub Copilot's preToolUse hook to the toolgate
// core.
//
// The field names and types below are based on the documented schema at:
// https://docs.github.com/en/copilot/reference/hooks-reference
// Specifically, the preToolUse input is:
//
//	{ sessionId: string, timestamp: number, cwd: string, toolName: string, toolArgs: unknown }
package copilot

import (
	"encoding/json"
	"strings"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/pathnorm"
)

// Adapter implements adapter.Adapter for GitHub Copilot.
type Adapter struct{}

func (Adapter) Name() string { return string(event.AgentCopilot) }

// input handles both camelCase (preToolUse) and VS Code compatible (PreToolUse)
// payload formats. The VS Code format uses snake_case field names and Claude
// tool names (e.g., "Bash" instead of "bash").
type input struct {
	// camelCase format fields
	ToolName  string           `json:"toolName"`
	ToolArgs  flexibleToolArgs `json:"toolArgs"`
	CWD       string           `json:"cwd"`
	SessionID string           `json:"sessionId"`

	// VS Code compatible format fields (snake_case)
	ToolNameSnake  string           `json:"tool_name"`
	ToolInputSnake flexibleToolArgs `json:"tool_input"`
	SessionIDSnake string           `json:"session_id"`
}

// getToolName returns the tool name from either format, preferring camelCase.
func (in *input) getToolName() string {
	if in.ToolName != "" {
		return in.ToolName
	}
	return in.ToolNameSnake
}

// getToolArgs returns the tool arguments from either format, preferring camelCase.
func (in *input) getToolArgs() flexibleToolArgs {
	if len(in.ToolArgs) > 0 {
		return in.ToolArgs
	}
	return in.ToolInputSnake
}

// getSessionID returns the session ID from either format, preferring camelCase.
func (in *input) getSessionID() string {
	if in.SessionID != "" {
		return in.SessionID
	}
	return in.SessionIDSnake
}

// flexibleToolArgs handles toolArgs which can be any JSON value (object, string,
// array, etc.) per the Copilot hooks reference: "toolArgs: unknown".
// We normalize it to map[string]any for internal use; non-object values become
// an empty map.
type flexibleToolArgs map[string]any

func (f *flexibleToolArgs) UnmarshalJSON(data []byte) error {
	// Try parsing as a map first (most common case)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err == nil {
		*f = m
		return nil
	}

	// If that fails, try parsing as a string containing JSON object
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if err := json.Unmarshal([]byte(s), &m); err == nil {
			*f = m
			return nil
		}
	}

	// For any other type (array, number, boolean, null, invalid JSON string),
	// return an empty map - we can't extract named arguments from these
	*f = make(map[string]any)
	return nil
}

// kindByTool maps Copilot's native tool names to capabilities. Unknown tools
// fall through to KindOther so the default action applies (never dropped).
//
// Tool names are based on the official GitHub Copilot hooks reference:
// https://docs.github.com/en/copilot/reference/hooks-reference
//
// Supports both runtime tool names (camelCase preToolUse) and Claude tool names
// (PascalCase PreToolUse / VS Code compatible format):
//
//	Runtime tool name        | Claude tool name
//	-------------------------|------------------
//	bash, powershell         | Bash
//	view                     | Read
//	create                   | Write
//	edit, str_replace_editor | Edit
//	apply_patch              | Edit
//	grep, rg                 | Grep
//	glob                     | Glob
var kindByTool = map[string]event.Kind{
	// Exec tools - runtime names
	"bash":       event.KindExec,
	"powershell": event.KindExec,
	// Exec tools - Claude name
	"Bash": event.KindExec,

	// File write tools - runtime names
	"create":             event.KindFileWrite,
	"write":              event.KindFileWrite,
	"edit":               event.KindFileWrite,
	"str_replace_editor": event.KindFileWrite,
	"apply_patch":        event.KindFileWrite,
	// File write tools - Claude names
	"Write": event.KindFileWrite,
	"Edit":  event.KindFileWrite,

	// File read tools - runtime names
	"view": event.KindFileRead,
	// File read tools - Claude names
	"Read": event.KindFileRead,

	// Search/navigation tools - runtime names
	"grep": event.KindFileRead,
	"rg":   event.KindFileRead,
	"glob": event.KindFileRead,
	// Search/navigation tools - Claude names
	"Grep": event.KindFileRead,
	"Glob": event.KindFileRead,
}

func (Adapter) Parse(raw []byte) (*event.Event, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}

	toolName := in.getToolName()
	toolArgs := in.getToolArgs()

	ev := &event.Event{
		Agent:     event.AgentCopilot,
		Tool:      toolName,
		CWD:       in.CWD,
		SessionID: in.getSessionID(),
		Input:     toolArgs,
	}

	if server, tool, ok := parseMCPName(toolName); ok {
		ev.Kind = event.KindMCP
		ev.MCP = event.MCP{Server: server, Tool: tool}
		return ev, nil
	}

	// Look up by exact name first (handles Claude tool names like "Bash", "Edit")
	// then fall back to lowercase for runtime names
	kind, known := kindByTool[toolName]
	if !known {
		kind, known = kindByTool[strings.ToLower(toolName)]
	}

	switch {
	case known && kind == event.KindExec:
		ev.Kind = event.KindExec
		ev.Cmd = stringArg(toolArgs, "command", "cmd", "script")
	case known:
		ev.Kind = kind
		if p := stringArg(toolArgs, "path", "file_path", "filePath", "filename"); p != "" {
			ev.Paths = normalizePaths(p, in.CWD)
		}
	default:
		ev.Kind = event.KindOther
	}
	return ev, nil
}

// parseMCPName recognizes MCP tool names. Copilot's exact MCP naming is
// unverified (TODO(schema)); both the Claude-style mcp__server__tool and a
// server/tool form are accepted.
func parseMCPName(name string) (server, tool string, ok bool) {
	if s := strings.TrimPrefix(name, "mcp__"); s != name {
		server, tool, found := strings.Cut(s, "__")
		if found && server != "" {
			return server, tool, true
		}
	}
	return "", "", false
}

func (Adapter) Render(action, reason string) ([]byte, error) {
	payload := struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	}{
		PermissionDecision:       action,
		PermissionDecisionReason: reason,
	}
	return json.Marshal(payload)
}

func stringArg(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func normalizePaths(raw, cwd string) []string {
	return pathnorm.WithResolved(pathnorm.Normalize(raw, cwd))
}
