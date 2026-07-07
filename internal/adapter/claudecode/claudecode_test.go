package claudecode

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
		wantMCP  event.MCP
		wantPath string // substring expected in Paths[0], "" to skip
	}{
		{
			name:     "bash is exec",
			payload:  `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/proj"}`,
			wantKind: event.KindExec,
			wantCmd:  "rm -rf /",
		},
		{
			name:     "write is file.write",
			payload:  `{"tool_name":"Write","tool_input":{"file_path":"a.txt"},"cwd":"/proj"}`,
			wantKind: event.KindFileWrite,
			wantPath: "/proj/a.txt",
		},
		{
			name:     "read is file.read",
			payload:  `{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"},"cwd":"/proj"}`,
			wantKind: event.KindFileRead,
			wantPath: "/etc/hosts",
		},
		{
			name:     "grep is file.search",
			payload:  `{"tool_name":"Grep","tool_input":{"path":"src"},"cwd":"/proj"}`,
			wantKind: event.KindFileSearch,
			wantPath: "/proj/src",
		},
		{
			name:     "mcp tool split",
			payload:  `{"tool_name":"mcp__github__create_issue","tool_input":{},"cwd":"/proj"}`,
			wantKind: event.KindMCP,
			wantMCP:  event.MCP{Server: "github", Tool: "create_issue"},
		},
		{
			name:     "unknown tool is other",
			payload:  `{"tool_name":"WebFetch","tool_input":{},"cwd":"/proj"}`,
			wantKind: event.KindOther,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := Adapter{}.Parse([]byte(tt.payload))
			require.NoError(t, err)
			assert.Equal(t, event.AgentClaudeCode, ev.Agent)
			assert.Equal(t, tt.wantKind, ev.Kind)
			assert.Equal(t, tt.wantCmd, ev.Cmd)
			assert.Equal(t, tt.wantMCP, ev.MCP)
			if tt.wantPath != "" {
				require.NotEmpty(t, ev.Paths)
				assert.Contains(t, ev.Paths, tt.wantPath)
			}
		})
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := Adapter{}.Parse([]byte(`{not json`))
	assert.Error(t, err)
}

func TestRender(t *testing.T) {
	out, err := Adapter{}.Render("deny", "blocked")
	require.NoError(t, err)

	var got map[string]map[string]string
	require.NoError(t, json.Unmarshal(out, &got))
	hs := got["hookSpecificOutput"]
	assert.Equal(t, "PreToolUse", hs["hookEventName"])
	assert.Equal(t, "deny", hs["permissionDecision"])
	assert.Equal(t, "blocked", hs["permissionDecisionReason"])
}
