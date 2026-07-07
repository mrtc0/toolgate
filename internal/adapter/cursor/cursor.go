// Package cursor adapts Cursor's beforeShellExecution / beforeReadFile /
// beforeMCPExecution hooks to the toolgate core.
//
// Cursor has no pre-write hook, so file writes cannot be gated for this agent;
// that gap is part of the threat model and is out of scope here.
//
// TODO(schema): field names (command, path, tool_name, server, workspace_roots
// and the permission/userMessage/agentMessage response) follow the documented
// shape but were not verified against https://cursor.com/docs/hooks at
// authoring time. Verify before release; assumptions are confined to this file.
package cursor

import (
	"encoding/json"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/pathnorm"
)

// Adapter implements adapter.Adapter for Cursor.
type Adapter struct{}

func (Adapter) Name() string { return string(event.AgentCursor) }

type input struct {
	HookEventName  string         `json:"hook_event_name"`
	Command        string         `json:"command"`
	Path           string         `json:"path"`
	FilePath       string         `json:"file_path"`
	ToolName       string         `json:"tool_name"`
	Server         string         `json:"server"`
	CWD            string         `json:"cwd"`
	WorkspaceRoots []string       `json:"workspace_roots"`
	ConversationID string         `json:"conversation_id"`
	ToolInput      map[string]any `json:"tool_input"`
}

func (Adapter) Parse(raw []byte) (*event.Event, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}

	cwd := in.CWD
	if cwd == "" && len(in.WorkspaceRoots) > 0 {
		cwd = in.WorkspaceRoots[0]
	}

	ev := &event.Event{
		Agent:     event.AgentCursor,
		Tool:      in.HookEventName,
		CWD:       cwd,
		SessionID: in.ConversationID,
		Input:     in.ToolInput,
	}

	switch in.HookEventName {
	case "beforeShellExecution":
		ev.Kind = event.KindExec
		ev.Cmd = in.Command
	case "beforeReadFile":
		ev.Kind = event.KindFileRead
		if p := firstNonEmpty(in.Path, in.FilePath); p != "" {
			ev.Paths = pathnorm.WithResolved(pathnorm.Normalize(p, cwd))
		}
	case "beforeMCPExecution":
		ev.Kind = event.KindMCP
		ev.MCP = event.MCP{Server: in.Server, Tool: in.ToolName}
	default:
		ev.Kind = event.KindOther
	}
	return ev, nil
}

// Render writes Cursor's permission response. deny/ask reasons are surfaced
// both to the user (userMessage) and to the agent (agentMessage).
func (Adapter) Render(action, reason string) ([]byte, error) {
	payload := struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"userMessage,omitempty"`
		AgentMessage string `json:"agentMessage,omitempty"`
	}{
		Permission:   action,
		UserMessage:  reason,
		AgentMessage: reason,
	}
	return json.Marshal(payload)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
