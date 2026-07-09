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

	// Policy health. The user layer and the project layer for the current
	// directory are loaded separately, so problems are attributed to the
	// right file.
	userPath := policy.UserPolicyPath()
	if _, err := os.Stat(userPath); err != nil {
		warn("no user policy at %s (default action applies to everything)", userPath)
	} else {
		checkPolicyLayer("user policy", userPath, "", ok, fail)
	}
	if cwd, err := os.Getwd(); err == nil {
		if projPath := policy.FindProjectPolicy(cwd); projPath != "" {
			checkPolicyLayer("project policy", "", projPath, ok, fail)
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

// checkPolicyLayer loads one policy layer (pass exactly one of userPath /
// projectPath) and reports every let and rule that does not compile — a
// broken let alone must not leave doctor silent. A healthy layer is reported
// with its rule count and its own default action.
func checkPolicyLayer(label, userPath, projectPath string, ok, fail func(string, ...any)) {
	path := userPath
	if path == "" {
		path = projectPath
	}
	pol, err := loadCompiled(userPath, projectPath)
	if err != nil {
		fail("%s %s does not load: %v", label, path, err)
		return
	}
	if pol.Broken {
		for _, l := range append(append([]policy.CompiledLet{}, pol.UserLets...), pol.ProjectLets...) {
			if l.Err != nil {
				fail("%s %s: %v", label, path, l.Err)
			}
		}
		for _, r := range pol.Rules {
			if r.Err != nil {
				fail("%s %s: %v", label, path, r.Err)
			}
		}
		return
	}
	def := pol.UserDefault
	if userPath == "" {
		def = pol.ProjectDefault
		if def == "" {
			def = "none (user policy's default applies)"
		}
	}
	ok("%s %s compiles (%d rules, default %s)", label, path, len(pol.Rules), def)
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
