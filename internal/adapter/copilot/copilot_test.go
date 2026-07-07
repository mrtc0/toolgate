package copilot

import (
	"encoding/json"
	"testing"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKindMapping(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantKind event.Kind
		wantCmd  string
		wantPath string
	}{
		// camelCase format (preToolUse) tests
		{
			name:     "bash is exec",
			payload:  `{"toolName":"bash","toolArgs":{"command":"rm -rf /"},"cwd":"/proj"}`,
			wantKind: event.KindExec,
			wantCmd:  "rm -rf /",
		},
		{
			name:     "str_replace_editor is file.write",
			payload:  `{"toolName":"str_replace_editor","toolArgs":{"path":"a.txt"},"cwd":"/proj"}`,
			wantKind: event.KindFileWrite,
			wantPath: "/proj/a.txt",
		},
		{
			name:     "view is file.read",
			payload:  `{"toolName":"view","toolArgs":{"file_path":"/etc/hosts"},"cwd":"/proj"}`,
			wantKind: event.KindFileRead,
			wantPath: "/etc/hosts",
		},
		{
			name:     "unknown tool is other, not dropped",
			payload:  `{"toolName":"mystery_tool","toolArgs":{},"cwd":"/proj"}`,
			wantKind: event.KindOther,
		},
		{
			name:     "toolArgs as JSON string (bash)",
			payload:  `{"toolName":"bash","toolArgs":"{\"command\":\"ls -la\"}","cwd":"/proj"}`,
			wantKind: event.KindExec,
			wantCmd:  "ls -la",
		},
		{
			name:     "toolArgs as JSON string (view)",
			payload:  `{"toolName":"view","toolArgs":"{\"path\":\"/etc/passwd\"}","cwd":"/proj"}`,
			wantKind: event.KindFileRead,
			wantPath: "/etc/passwd",
		},
		// VS Code compatible format (PreToolUse) tests - Claude tool names
		{
			name:     "VS Code format: Bash (Claude name) is exec",
			payload:  `{"tool_name":"Bash","tool_input":{"command":"echo hello"},"cwd":"/proj","session_id":"abc"}`,
			wantKind: event.KindExec,
			wantCmd:  "echo hello",
		},
		{
			name:     "VS Code format: Read (Claude name) is file.read",
			payload:  `{"tool_name":"Read","tool_input":{"path":"/etc/hosts"},"cwd":"/proj"}`,
			wantKind: event.KindFileRead,
			wantPath: "/etc/hosts",
		},
		{
			name:     "VS Code format: Write (Claude name) is file.write",
			payload:  `{"tool_name":"Write","tool_input":{"path":"new.txt"},"cwd":"/proj"}`,
			wantKind: event.KindFileWrite,
			wantPath: "/proj/new.txt",
		},
		{
			name:     "VS Code format: Edit (Claude name) is file.write",
			payload:  `{"tool_name":"Edit","tool_input":{"path":"edit.txt"},"cwd":"/proj"}`,
			wantKind: event.KindFileWrite,
			wantPath: "/proj/edit.txt",
		},
		{
			name:     "VS Code format: Grep (Claude name) is file.read",
			payload:  `{"tool_name":"Grep","tool_input":{},"cwd":"/proj"}`,
			wantKind: event.KindFileRead,
		},
		{
			name:     "VS Code format: Glob (Claude name) is file.read",
			payload:  `{"tool_name":"Glob","tool_input":{},"cwd":"/proj"}`,
			wantKind: event.KindFileRead,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := Adapter{}.Parse([]byte(tt.payload))
			require.NoError(t, err)
			assert.Equal(t, event.AgentCopilot, ev.Agent)
			assert.Equal(t, tt.wantKind, ev.Kind)
			assert.Equal(t, tt.wantCmd, ev.Cmd)
			if tt.wantPath != "" {
				assert.Contains(t, ev.Paths, tt.wantPath)
			}
		})
	}
}

func TestRender(t *testing.T) {
	out, err := Adapter{}.Render("ask", "confirm")
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "ask", got["permissionDecision"])
	assert.Equal(t, "confirm", got["permissionDecisionReason"])
}
