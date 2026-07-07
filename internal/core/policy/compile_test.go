package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileAcceptsNormalizedVariables(t *testing.T) {
	tests := []struct {
		name string
		when string
	}{
		{"agent", `agent == "cursor"`},
		{"kind", `kind == "exec"`},
		{"kind prefix", `kind.startsWith("file.")`},
		{"mcp map", `kind == "mcp" && mcp.server == "github"`},
		{"session_id", `session_id != ""`},
		{"legacy tool", `tool == "Bash"`},
		{"cmds still present", `cmds.exists(c, c.name == "rm")`},
		// Unified path variables
		{"reads", `reads.exists(p, p.startsWith("/etc/"))`},
		{"writes", `writes.all(p, p.startsWith(cwd + "/"))`},
		{"accesses", `accesses.size() > 0`},
		// Custom functions
		{"glob function", `path.glob(".env")`},
		{"glob with brace", `path.glob("{.env,.env.*}")`},
		{"under function", `path.under(cwd)`},
		{"in_tmp function", `path.in_tmp()`},
		{"glob in exists", `reads.exists(p, p.glob("*.go"))`},
		{"under in all", `writes.all(p, p.under(cwd) || p.in_tmp())`},
		// arg_paths in cmds
		{"arg_paths", `cmds.exists(c, c.arg_paths.exists(p, p.endsWith(".env")))`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Default: ActionAsk, Rules: []Rule{
				{Name: "r", Action: ActionDeny, When: tt.when},
			}}
			c, err := p.Compile()
			require.NoError(t, err)
			assert.False(t, c.Broken, "rule should compile: %s", tt.when)
		})
	}
}

func TestCompileReportsBrokenRule(t *testing.T) {
	p := &Policy{Default: ActionAsk, Rules: []Rule{
		{Name: "bad", Action: ActionDeny, When: `nope.does.not.exist`},
	}}
	c, err := p.Compile()
	require.NoError(t, err)
	assert.True(t, c.Broken)
	require.Len(t, c.Rules, 1)
	assert.Error(t, c.Rules[0].Err)
}

func TestCompileRejectsNonBoolExpression(t *testing.T) {
	p := &Policy{Default: ActionAsk, Rules: []Rule{
		{Name: "str", Action: ActionDeny, When: `"not a bool"`},
	}}
	c, err := p.Compile()
	require.NoError(t, err)
	assert.True(t, c.Broken)
}

func TestCompileLets(t *testing.T) {
	tests := []struct {
		name       string
		lets       []Let
		when       string
		wantBroken bool
	}{
		{
			name: "simple let",
			lets: []Let{{Name: "ro_cmds", Expr: `["cat", "head", "grep"]`}},
			when: `cmds.exists(c, c.name in ro_cmds)`,
		},
		{
			name: "chained lets",
			lets: []Let{
				{Name: "safe_dirs", Expr: `[cwd, home + "/.config"]`},
				{Name: "all_safe", Expr: `paths.all(p, safe_dirs.exists(d, p.startsWith(d)))`},
			},
			when: `all_safe`,
		},
		{
			name: "let with filter",
			lets: []Let{{Name: "outside_writes", Expr: `writes.filter(p, !p.under(cwd) && !p.in_tmp())`}},
			when: `outside_writes.size() > 0`,
		},
		{
			name:       "broken let expr",
			lets:       []Let{{Name: "bad", Expr: `undefined_var`}},
			when:       `true`,
			wantBroken: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Default:  ActionAsk,
				UserLets: tt.lets,
				Rules:    []Rule{{Name: "r", Action: ActionDeny, When: tt.when, Source: "user"}},
			}
			c, err := p.Compile()
			require.NoError(t, err)
			assert.Equal(t, tt.wantBroken, c.Broken, "Broken mismatch")
		})
	}
}

func TestCompileLetsSourceIsolation(t *testing.T) {
	// User and project lets with same name should be isolated
	p := &Policy{
		Default:     ActionAsk,
		UserLets:    []Let{{Name: "x", Expr: `"user_value"`}},
		ProjectLets: []Let{{Name: "x", Expr: `"project_value"`}},
		Rules: []Rule{
			{Name: "user_rule", Action: ActionDeny, When: `x == "user_value"`, Source: "user"},
			{Name: "project_rule", Action: ActionAsk, When: `x == "project_value"`, Source: "project"},
		},
	}
	c, err := p.Compile()
	require.NoError(t, err)
	assert.False(t, c.Broken)
	// Both rules should compile successfully using their respective scopes
	for _, cr := range c.Rules {
		assert.NoError(t, cr.Err, "rule %q should compile", cr.Rule.Name)
	}
}

func TestCompileLetsTypeInference(t *testing.T) {
	p := &Policy{
		Default:  ActionAsk,
		UserLets: []Let{{Name: "count", Expr: `5`}},
		// Using count in arithmetic should work (inferred as int)
		Rules: []Rule{{Name: "r", Action: ActionDeny, When: `paths.size() > count`, Source: "user"}},
	}
	c, err := p.Compile()
	require.NoError(t, err)
	assert.False(t, c.Broken)
	// Verify the let was compiled with correct type
	require.Len(t, c.UserLets, 1)
	assert.NotNil(t, c.UserLets[0].Type)
}
