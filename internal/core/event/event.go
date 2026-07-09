// Package event defines the agent-agnostic tool call that the core evaluates.
// Adapters translate each agent's native hook payload into an Event so that
// policies are written against capabilities (Kind) rather than agent-specific
// tool names.
package event

// Agent identifies which coding agent produced the event.
type Agent string

const (
	AgentClaudeCode Agent = "claude-code"
	AgentCopilot    Agent = "copilot"
	AgentCursor     Agent = "cursor"
)

// Kind is the normalized capability a tool call exercises. Policies match on
// Kind so one rule set is portable across agents.
type Kind string

const (
	KindExec       Kind = "exec"       // shell command execution
	KindFileRead   Kind = "file.read"  // reading a file
	KindFileWrite  Kind = "file.write" // creating, editing or deleting a file
	KindFileSearch Kind = "file.search"
	KindMCP        Kind = "mcp" // MCP tool invocation
	KindOther      Kind = "other"
)

// MCP carries the server/tool split for KindMCP events; zero value otherwise.
type MCP struct {
	Server string
	Tool   string
}

// Event is the normalized tool call the core engine evaluates. Adapters fill
// the fields relevant to the event's Kind and leave the rest at their zero
// value. Paths must already be normalized to absolute paths by the adapter
// (via pathnorm) so the core stays free of filesystem I/O.
type Event struct {
	Agent Agent
	Kind  Kind
	Tool  string   // agent-native tool name; escape hatch for rules
	Cmd   string   // shell command string; "" unless Kind == KindExec
	Paths []string // normalized absolute paths the call touches
	MCP   MCP      // populated only when Kind == KindMCP
	CWD   string   // working directory of the tool call
	// Home is the user's home directory ("" if unknown), injected by the
	// imperative shell so policies can match home-relative paths portably
	// (e.g. paths.exists(p, p.startsWith(home + "/.ssh/"))) without a username.
	Home string
	// ConfigDir is toolgate's config directory (policy.ConfigDir()), injected by
	// the imperative shell so self-protection can guard the user policy and
	// defaults overrides regardless of where XDG_CONFIG_HOME relocates them.
	ConfigDir string
	SessionID string         // "" when the agent provides no session id
	Input     map[string]any // raw tool input; escape hatch for rules
}
