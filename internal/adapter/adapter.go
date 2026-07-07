// Package adapter is the port between each coding agent's native hook wire
// format and the toolgate core. An Adapter parses an agent's stdin payload
// into a normalized event.Event and renders a decision back into that agent's
// expected stdout JSON. All agent-specific, version-fragile knowledge lives in
// the concrete adapters; the core never sees it.
package adapter

import (
	"fmt"

	"github.com/mrtc0/toolgate/internal/adapter/claudecode"
	"github.com/mrtc0/toolgate/internal/adapter/copilot"
	"github.com/mrtc0/toolgate/internal/adapter/cursor"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// Adapter translates one agent's hook protocol to and from the core model.
type Adapter interface {
	// Name is the agent identifier used on the command line (e.g. "cursor").
	Name() string
	// Parse converts a raw stdin payload into a normalized event.
	Parse(raw []byte) (*event.Event, error)
	// Render converts a final decision (action plus a human-readable reason)
	// into the full stdout payload the agent expects.
	Render(action, reason string) ([]byte, error)
}

// ByName returns the adapter for an agent identifier, or an error listing the
// supported agents.
func ByName(name string) (Adapter, error) {
	switch name {
	case string(event.AgentClaudeCode):
		return claudecode.Adapter{}, nil
	case string(event.AgentCopilot):
		return copilot.Adapter{}, nil
	case string(event.AgentCursor):
		return cursor.Adapter{}, nil
	default:
		return nil, fmt.Errorf("unknown agent %q (supported: %s, %s, %s)",
			name, event.AgentClaudeCode, event.AgentCopilot, event.AgentCursor)
	}
}

// Names lists the supported agent identifiers.
func Names() []string {
	return []string{
		string(event.AgentClaudeCode),
		string(event.AgentCopilot),
		string(event.AgentCursor),
	}
}
