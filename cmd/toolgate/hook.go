package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mrtc0/toolgate/internal/adapter"
	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/core/policy"
	"github.com/spf13/cobra"
)

func newHookCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hook <agent>",
		Short: "run as a hook: read the tool call JSON from stdin and write the permission decision JSON to stdout",
		Long: fmt.Sprintf(`Run as a hook: read the tool call JSON from stdin and write the
permission decision JSON to stdout (agent: %s, %s, %s).`,
			event.AgentClaudeCode, event.AgentCopilot, event.AgentCursor),
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runHook(args))
		},
	}
}

func runHook(args []string) int {
	if len(args) == 0 {
		return exitf(2, "toolgate hook: missing agent (one of: %s)\n", joinAgents())
	}
	ad, err := adapter.ByName(args[0])
	if err != nil {
		return exitf(2, "toolgate hook: %v\n", err)
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputSize))
	if err != nil {
		return emit(ad, nil, engine.Decision{
			Action: failClosedAction(), Rule: "builtin:input-error",
			Message: fmt.Sprintf("toolgate could not read hook input: %v", err),
		})
	}

	ev, err := ad.Parse(raw)
	if err != nil {
		return emit(ad, nil, engine.Decision{
			Action: failClosedAction(), Rule: "builtin:input-error",
			Message: fmt.Sprintf("toolgate could not parse %s hook input: %v", ad.Name(), err),
		})
	}
	ev.Home = homeDir()
	ev.ConfigDir = policy.ConfigDir()
	engine.SaveLastInput(ad.Name(), ev.SessionID, raw)

	pol, err := loadCompiled(policy.UserPolicyPath(), policy.FindProjectPolicy(ev.CWD))
	if err != nil {
		return emit(ad, ev, engine.Decision{
			Action: failClosedAction(), Rule: "builtin:policy-error",
			Message: fmt.Sprintf("toolgate policy error: %v", err),
		})
	}

	d := engine.Evaluate(ev, pol, engine.Options{FailOpen: failOpen()})
	return emit(ad, ev, d)
}

// emit renders the decision through the adapter, handling dry-run,
// stderr warnings and decision logging.
func emit(ad adapter.Adapter, ev *event.Event, d engine.Decision) int {
	if failOpen() {
		fmt.Fprintln(os.Stderr, "toolgate: warning: TOOLGATE_FAIL_OPEN=1 is set; failures are allowed through and safety is reduced")
	}
	for _, w := range d.Warnings {
		fmt.Fprintln(os.Stderr, "toolgate: warning: "+w)
	}

	out := d
	dry := dryRun()
	if dry && d.Action != policy.ActionAllow {
		out.Action = policy.ActionAllow
		out.Message = fmt.Sprintf("[dry-run] would be %q by rule %q: %s", d.Action, d.Rule, d.Message)
	}

	if logPath := os.Getenv(envLog); logPath != "" && ev != nil {
		if err := engine.WriteLog(logPath, ev, d, dry); err != nil {
			fmt.Fprintf(os.Stderr, "toolgate: warning: could not write decision log: %v\n", err)
		}
	}

	reason := out.Message
	if reason == "" && out.Action != policy.ActionAllow {
		reason = fmt.Sprintf("toolgate: %s by rule %q", out.Action, out.Rule)
	}
	payload, err := ad.Render(out.Action, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "toolgate: could not render decision: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, string(payload))
	return 0
}
