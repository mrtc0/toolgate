package cursor

import (
	"encoding/json"
	"testing"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEventDispatch(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantKind event.Kind
		wantCmd  string
		wantMCP  event.MCP
		wantPath string
	}{
		{
			name:     "shell execution is exec",
			payload:  `{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/proj"}`,
			wantKind: event.KindExec,
			wantCmd:  "rm -rf /",
		},
		{
			name:     "read file is file.read",
			payload:  `{"hook_event_name":"beforeReadFile","path":".env","workspace_roots":["/proj"]}`,
			wantKind: event.KindFileRead,
			wantPath: "/proj/.env",
		},
		{
			name:     "mcp execution is mcp",
			payload:  `{"hook_event_name":"beforeMCPExecution","server":"github","tool_name":"create_issue"}`,
			wantKind: event.KindMCP,
			wantMCP:  event.MCP{Server: "github", Tool: "create_issue"},
		},
		{
			name:     "unknown event is other",
			payload:  `{"hook_event_name":"afterFileEdit"}`,
			wantKind: event.KindOther,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := Adapter{}.Parse([]byte(tt.payload))
			require.NoError(t, err)
			assert.Equal(t, event.AgentCursor, ev.Agent)
			assert.Equal(t, tt.wantKind, ev.Kind)
			assert.Equal(t, tt.wantCmd, ev.Cmd)
			assert.Equal(t, tt.wantMCP, ev.MCP)
			if tt.wantPath != "" {
				assert.Contains(t, ev.Paths, tt.wantPath)
			}
		})
	}
}

func TestRenderDenyCarriesBothMessages(t *testing.T) {
	out, err := Adapter{}.Render("deny", "blocked by rule X")
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "deny", got["permission"])
	assert.Equal(t, "blocked by rule X", got["userMessage"])
	assert.Equal(t, "blocked by rule X", got["agentMessage"])
}
