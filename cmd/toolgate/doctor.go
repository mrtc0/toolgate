package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrtc0/toolgate/internal/core/policy"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "check hook registration and policy health",
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runDoctor())
		},
	}
}

// runDoctor checks that toolgate is healthy: the policy loads and compiles,
// and each agent's hook config (where present) registers toolgate. Cursor
// configs without failClosed are reported as errors. It exits non-zero
// if any error-level problem is found.
func runDoctor() int {
	var problems int
	ok := func(format string, a ...any) { fmt.Printf("ok:    "+format+"\n", a...) }
	warn := func(format string, a ...any) { fmt.Printf("warn:  "+format+"\n", a...) }
	fail := func(format string, a ...any) { fmt.Printf("error: "+format+"\n", a...); problems++ }

	// Policy health.
	userPath := policy.UserPolicyPath()
	if _, err := os.Stat(userPath); err != nil {
		warn("no user policy at %s (default action applies to everything)", userPath)
	} else if pol, err := loadCompiled(userPath, ""); err != nil {
		fail("user policy %s does not load: %v", userPath, err)
	} else {
		if pol.Broken {
			for _, r := range pol.Rules {
				if r.Err != nil {
					fail("policy rule %q does not compile: %v", r.Rule.Name, r.Err)
				}
			}
		} else {
			ok("user policy %s compiles (%d rules, default %s)", userPath, len(pol.Rules), pol.Default)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		warn("cannot resolve home directory: %v", err)
		return exitCode(problems)
	}

	// Claude Code.
	checkHookFile(filepath.Join(home, ".claude", "settings.json"), ok, warn, fail, false)
	// Copilot.
	checkHookFile(filepath.Join(home, ".copilot", "hooks", "toolgate.json"), ok, warn, fail, false)
	// Cursor: failClosed is required.
	checkHookFile(filepath.Join(home, ".cursor", "hooks.json"), ok, warn, fail, true)

	return exitCode(problems)
}

func exitCode(problems int) int {
	if problems > 0 {
		return 1
	}
	return 0
}

// checkHookFile reports whether a hook config registers toolgate. When
// requireFailClosed is set (Cursor), a config that registers toolgate but omits
// failClosed is an error.
func checkHookFile(path string, ok, warn, fail func(string, ...any), requireFailClosed bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		warn("no hook config at %s (toolgate not registered there)", path)
		return
	}
	text := string(data)
	if !strings.Contains(text, "toolgate") {
		warn("%s exists but does not register toolgate", path)
		return
	}
	if requireFailClosed && !strings.Contains(text, "failClosed") {
		fail("%s registers toolgate without failClosed: true (Cursor fails open by default; add it)", path)
		return
	}
	ok("%s registers toolgate", path)
}
