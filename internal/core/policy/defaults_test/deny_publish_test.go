package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
)

// TestDenyPublishDefaultPolicy loads defaults:deny-publish with a default allow
// so scenarios assert exactly which publishing commands are blocked.
func TestDenyPublishDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:deny-publish
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, cmd, action, rule string
	}{
		{"npm-publish", "npm publish", "deny", "deny-package-publish"},
		{"pnpm-publish", "pnpm publish", "deny", "deny-package-publish"},
		{"yarn-publish", "yarn publish", "deny", "deny-package-publish"},
		{"cargo-publish", "cargo publish", "deny", "deny-package-publish"},
		{"gem-push", "gem push mygem-1.0.0.gem", "deny", "deny-package-publish"},
		{"twine-upload", "twine upload dist/*", "deny", "deny-package-publish"},
		{"poetry-publish", "poetry publish", "deny", "deny-package-publish"},
		{"goreleaser", "goreleaser release", "deny", "deny-package-publish"},

		{"npm-install", "npm install", "allow", "default"},
		{"cargo-build", "cargo build", "allow", "default"},
		{"gem-install", "gem install foo", "allow", "default"},
		{"poetry-add", "poetry add requests", "allow", "default"},

		{"unrelated", "ls -la", "allow", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Evaluate(enginetest.BashInput(tc.cmd), pol, engine.Options{})
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("cmd %q: got (%s, %s), want (%s, %s)", tc.cmd, d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}
