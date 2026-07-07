package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
)

// TestGitDefaultPolicy loads defaults:git with default allow so that scenarios
// assert exactly which commands the git rules gate.
func TestGitDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:git
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, cmd, action, rule string
	}{
		{"force-push", "git push --force origin main", "ask", "ask-git-force-push"},
		{"force-push-short", "git push -f origin main", "ask", "ask-git-force-push"},
		{"force-with-lease", "git push --force-with-lease=main origin main", "ask", "ask-git-force-push"},
		{"push-mirror", "git push --mirror backup", "ask", "ask-git-force-push"},
		{"plain-push", "git push origin main", "allow", "default"},

		{"push-delete", "git push --delete origin topic", "ask", "ask-git-push-delete"},
		{"push-colon-refspec", "git push origin :topic", "ask", "ask-git-push-delete"},

		{"rebase", "git rebase main", "ask", "ask-git-history-rewrite"},
		{"filter-branch", "git filter-branch --tree-filter 'rm -f secret' HEAD", "ask", "ask-git-history-rewrite"},
		{"commit-amend", "git commit --amend --no-edit", "ask", "ask-git-history-rewrite"},
		{"plain-commit", "git commit -m 'fix bug'", "allow", "default"},

		{"reset-hard", "git reset --hard HEAD~1", "ask", "ask-git-discard-changes"},
		{"reset-soft", "git reset --soft HEAD~1", "allow", "default"},
		{"checkout-force", "git checkout -f main", "ask", "ask-git-discard-changes"},
		{"plain-checkout", "git checkout main", "allow", "default"},
		{"restore-worktree", "git restore src/main.go", "ask", "ask-git-discard-changes"},
		{"restore-staged", "git restore --staged src/main.go", "allow", "default"},
		{"clean-force", "git clean -fd", "ask", "ask-git-discard-changes"},
		{"clean-dry-run", "git clean -nd", "allow", "default"},

		{"branch-force-delete", "git branch -D topic", "ask", "ask-git-force-ref-update"},
		{"branch-safe-delete", "git branch -d topic", "allow", "default"},
		{"tag-delete", "git tag -d v1.0.0", "ask", "ask-git-force-ref-update"},
		{"plain-tag", "git tag v1.0.0", "allow", "default"},

		{"reflog-expire", "git reflog expire --expire=now --all", "ask", "ask-git-destroy-recovery"},
		{"gc-prune", "git gc --prune=now", "ask", "ask-git-destroy-recovery"},
		{"stash-clear", "git stash clear", "ask", "ask-git-destroy-recovery"},
		{"stash-pop", "git stash pop", "allow", "default"},

		{"commit-no-verify", "git commit --no-verify -m x", "ask", "ask-git-no-verify"},
		{"commit-n", "git commit -n -m x", "ask", "ask-git-no-verify"},
		{"push-no-verify", "git push --no-verify", "ask", "ask-git-no-verify"},

		{"remote-set-url", "git remote set-url origin git@example.com:x/y.git", "ask", "ask-git-remote-modify"},

		{"config-hookspath", "git config core.hooksPath /tmp/hooks", "ask", "ask-git-config-dangerous-keys"},
		{"inline-config-ssh", "git -c core.sshCommand='ssh -A' fetch", "ask", "ask-git-config-dangerous-keys"},
		{"config-username", "git config user.name mrtc0", "allow", "default"},

		{"submodule-foreach", "git submodule foreach 'git checkout main'", "ask", "ask-git-submodule-foreach"},
		{"submodule-update", "git submodule update --init", "allow", "default"},

		// Read-only inspection commands are auto-allowed.
		{"status", "git status", "allow", "allow-git-read-only"},
		{"log", "git log --oneline -10", "allow", "allow-git-read-only"},
		{"diff", "git diff HEAD~1", "allow", "allow-git-read-only"},
		{"show", "git show HEAD", "allow", "allow-git-read-only"},
		{"blame", "git blame README.md", "allow", "allow-git-read-only"},
		{"rev-parse", "git rev-parse HEAD", "allow", "allow-git-read-only"},
		{"ls-files", "git ls-files", "allow", "allow-git-read-only"},
		{"read-only-chain", "git status && git log", "allow", "allow-git-read-only"},
		// diff --output writes a file, so it is not swept into the allow.
		{"diff-output-write", "git diff --output=/tmp/x", "allow", "default"},
		// A chain mixing a non-git command does not match cmds.all.
		{"mixed-chain", "git log && echo hi", "allow", "default"},

		// Read-only forms of otherwise-mutating subcommands are allowed.
		{"remote-list", "git remote -v", "allow", "allow-git-read-only-subcommands"},
		{"remote-show", "git remote show origin", "allow", "allow-git-read-only-subcommands"},
		{"remote-add", "git remote add up git@x:y.git", "allow", "default"},
		{"config-get", "git config --get user.name", "allow", "allow-git-read-only-subcommands"},
		{"config-list", "git config --list", "allow", "allow-git-read-only-subcommands"},
		{"stash-list", "git stash list", "allow", "allow-git-read-only-subcommands"},
		{"worktree-list", "git worktree list", "allow", "allow-git-read-only-subcommands"},
		{"submodule-status", "git submodule status", "allow", "allow-git-read-only-subcommands"},
		{"branch-list", "git branch --list", "allow", "allow-git-read-only-subcommands"},
		{"branch-all", "git branch -a", "allow", "allow-git-read-only-subcommands"},
		{"tag-list", "git tag -l", "allow", "allow-git-read-only-subcommands"},

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
