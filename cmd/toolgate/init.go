package main

import (
	"fmt"
	"os"

	"github.com/mrtc0/toolgate/internal/adapter"
	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var agentName string
	cmd := &cobra.Command{
		Use:   "init --agent <agent>",
		Short: "print hook configuration for an agent",
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runInit(agentName))
		},
	}
	cmd.Flags().StringVar(&agentName, "agent", "", "agent to print hook config for (claude-code, copilot, cursor)")
	return cmd
}

// runInit prints the hook configuration for an agent. It never writes files:
// the snippet is meant to be reviewed and merged by a human (and the recommended
// self-protection policy denies writes to these files anyway).
func runInit(agentName string) int {
	if agentName == "" {
		return exitf(2, "toolgate init: --agent is required (one of: %s)\n", joinAgents())
	}
	if _, err := adapter.ByName(agentName); err != nil {
		return exitf(2, "toolgate init: %v\n", err)
	}

	bin := toolgateBinary()
	switch event.Agent(agentName) {
	case event.AgentClaudeCode:
		fmt.Print(claudeInitSnippet(bin))
	case event.AgentCopilot:
		fmt.Print(copilotInitSnippet(bin))
	case event.AgentCursor:
		fmt.Print(cursorInitSnippet(bin))
	}
	return 0
}

// toolgateBinary returns a command that invokes this binary. When toolgate is
// on PATH the bare name is cleaner; otherwise use the absolute path.
func toolgateBinary() string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "toolgate"
}

func claudeInitSnippet(bin string) string {
	return fmt.Sprintf(`# Claude Code: add to ~/.claude/settings.json (or the project .claude/settings.json)

{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|Glob|mcp__.*",
        "hooks": [{ "type": "command", "command": "%s hook claude-code" }]
      }
    ]
  }
}
`, bin)
}

func copilotInitSnippet(bin string) string {
	return fmt.Sprintf(`# GitHub Copilot: save as ~/.copilot/hooks/toolgate.json
# (or a repo .github/hooks/toolgate.json)

{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "command": "%s hook copilot" }
    ]
  }
}
`, bin)
}

func cursorInitSnippet(bin string) string {
	// failClosed: true is mandatory for Cursor, whose hooks default to
	// fail-open. doctor flags its absence.
	return fmt.Sprintf(`# Cursor: save as ~/.cursor/hooks.json (or the project .cursor/hooks.json)

{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "%[1]s hook cursor", "failClosed": true }
    ],
    "beforeReadFile": [
      { "command": "%[1]s hook cursor", "failClosed": true }
    ],
    "beforeMCPExecution": [
      { "command": "%[1]s hook cursor", "failClosed": true }
    ]
  }
}
`, bin)
}
