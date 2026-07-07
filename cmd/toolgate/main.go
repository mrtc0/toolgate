// toolgate is a policy gate that runs as a pre-tool-use hook for coding
// agents (Claude Code, GitHub Copilot, Cursor). It reads a tool call from
// stdin, evaluates it against a CEL policy, and writes an allow/ask/deny
// decision to stdout.
package main

import (
	"fmt"
	"os"

	"github.com/mrtc0/toolgate/internal/adapter"
	"github.com/mrtc0/toolgate/internal/core/policy"
	"github.com/mrtc0/toolgate/version"
	"github.com/spf13/cobra"
)

// maxInputSize caps the stdin payload we are willing to parse.
const maxInputSize = 8 << 20 // 8 MiB

// Environment variables that tune the hook.
const (
	envLog      = "TOOLGATE_LOG"
	envDryRun   = "TOOLGATE_DRY_RUN"
	envFailOpen = "TOOLGATE_FAIL_OPEN"
)

func main() {
	// Subcommands exit via os.Exit inside their Run funcs, so any error that
	// surfaces here is a cobra usage/parse error; keep the historical code 2.
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "toolgate",
		Short: "a policy gate for coding-agent tool calls",
		Long: `toolgate - a policy gate for coding-agent tool calls

Environment:
  TOOLGATE_LOG=<path>      append decision logs as JSON Lines
  TOOLGATE_DRY_RUN=1       always answer allow, but log the real decision
  TOOLGATE_FAIL_OPEN=1     answer allow instead of ask/deny on internal
                           failures (NOT recommended; reduces safety)`,
		Version: version.Version,
	}
	root.SetVersionTemplate("toolgate {{.Version}}\n")
	root.AddCommand(
		newHookCmd(),
		newInitCmd(),
		newDoctorCmd(),
	)
	return root
}

func boolEnv(name string) bool {
	v := os.Getenv(name)
	return v == "1" || v == "true"
}

// homeDir resolves the user's home directory for the `home` policy variable.
// Best-effort: an empty string simply means home-relative rules do not match.
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func failOpen() bool { return boolEnv(envFailOpen) }
func dryRun() bool   { return boolEnv(envDryRun) }

// failClosedAction is what we answer when toolgate itself is broken.
func failClosedAction() string {
	if failOpen() {
		return policy.ActionAllow
	}
	return policy.ActionDeny
}

func loadCompiled(userPath, projectPath string) (*policy.Compiled, error) {
	pol, err := policy.Load(userPath, projectPath)
	if err != nil {
		return nil, err
	}
	return pol.Compile()
}

func joinAgents() string {
	out := ""
	for i, n := range adapter.Names() {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// exitf prints a message to stderr and returns the given exit code, so command
// runners can keep their flat error-handling style.
func exitf(code int, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format, a...)
	return code
}
