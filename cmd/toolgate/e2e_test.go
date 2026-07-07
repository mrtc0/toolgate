package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// e2ePolicy denies rm -rf against any agent by matching on the exec
// capability, and carries the recommended self-protection rules (agent hook
// configs are no longer protected by a built-in: it is ordinary policy now).
const e2ePolicy = `
version: 1
default: ask
rules:
  - name: deny-rm-rf
    action: deny
    when: |
      kind == "exec" &&
      cmds.exists(c,
        c.name == "rm" &&
        c.flags.exists(f, f == "r" || f == "recursive") &&
        c.flags.exists(f, f == "f" || f == "force"))
  - name: protect-gate-config-file-tools
    action: deny
    when: |
      kind == "file.write" &&
      paths.exists(p,
        p.matches(r'(^|/)\.cursor/hooks\.json$') ||
        p.contains("/.copilot/hooks/"))
  - name: protect-gate-config-bash
    action: deny
    when: |
      kind == "exec" &&
      cmds.exists(c,
        c.writes_to.exists(p, p.matches(r'(^|/)\.cursor/hooks\.json$')) ||
        c.args.exists(a, a.matches(r'(^|/)\.cursor/hooks\.json$')))
`

// buildToolgate compiles the CLI once for the E2E table.
func buildToolgate(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "toolgate")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	require.NoError(t, err, "build failed: %s", out)
	return bin
}

func TestE2EAllAdapters(t *testing.T) {
	bin := buildToolgate(t)

	home := t.TempDir()
	config := t.TempDir()
	cache := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(config, "toolgate"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(config, "toolgate", "policy.yaml"), []byte(e2ePolicy), 0o600))

	env := append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+config,
		"XDG_CACHE_HOME="+cache,
	)

	// Self-protection targets resolved under the controlled home.
	cursorHooks := filepath.Join(home, ".cursor", "hooks.json")
	copilotHook := filepath.Join(home, ".copilot", "hooks", "toolgate.json")

	tests := []struct {
		name    string
		agent   string
		stdin   string
		wantDec string // action expected in the rendered JSON
	}{
		{"claude rm-rf", "claude-code", `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"},"cwd":"/tmp"}`, "deny"},
		{"claude normal", "claude-code", `{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/tmp"}`, "ask"},
		{"claude self-defense", "claude-code", `{"tool_name":"Write","tool_input":{"file_path":"` + cursorHooks + `"},"cwd":"/tmp"}`, "deny"},

		{"copilot rm-rf", "copilot", `{"toolName":"bash","toolArgs":{"command":"rm -rf /tmp/x"},"cwd":"/tmp"}`, "deny"},
		{"copilot normal", "copilot", `{"toolName":"bash","toolArgs":{"command":"ls -la"},"cwd":"/tmp"}`, "ask"},
		{"copilot self-defense", "copilot", `{"toolName":"write","toolArgs":{"path":"` + copilotHook + `"},"cwd":"/tmp"}`, "deny"},

		{"cursor rm-rf", "cursor", `{"hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/x","cwd":"/tmp"}`, "deny"},
		{"cursor normal", "cursor", `{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/tmp"}`, "ask"},
		{"cursor self-defense", "cursor", `{"hook_event_name":"beforeShellExecution","command":"rm ` + cursorHooks + `","cwd":"/tmp"}`, "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bin, "hook", tt.agent)
			cmd.Env = env
			cmd.Stdin = strings.NewReader(tt.stdin)
			out, err := cmd.Output()
			require.NoError(t, err, "stderr/exit for %s", tt.name)
			// Each adapter renders the action under a different JSON key, so a
			// substring assertion keeps the table agent-agnostic.
			assert.Contains(t, string(out), `"`+tt.wantDec+`"`,
				"decision for %s: %s", tt.name, out)
		})
	}
}
