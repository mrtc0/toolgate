package policy

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobFunction(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		// Basic patterns
		{"exact match", "/proj/.env", ".env", true},
		{"exact match deep", "/proj/src/config/.env", ".env", true},
		{"no match", "/proj/README.md", ".env", false},

		// Implicit **/ prefix for non-rooted patterns
		{"implicit anchor top", "/proj/.env", ".env", true},
		{"implicit anchor nested", "/proj/a/b/c/.env", ".env", true},
		{"implicit anchor with dir", "/proj/src/.env", "src/.env", true},

		// Rooted patterns (start with /)
		{"rooted exact", "/proj/.env", "/proj/.env", true},
		{"rooted no match", "/proj/.env", "/other/.env", false},
		{"rooted wildcard", "/proj/src/file.go", "/proj/**/*.go", true},

		// Brace expansion
		{"brace single", "/proj/.env", "{.env,.env.*}", true},
		{"brace dotenv local", "/proj/.env.local", "{.env,.env.*}", true},
		{"brace dotenv prod", "/proj/.env.production", "{.env,.env.*}", true},
		{"brace no match", "/proj/README.md", "{.env,.env.*}", false},

		// Wildcard patterns
		{"star wildcard", "/proj/file.go", "*.go", true},
		{"star wildcard no match", "/proj/file.txt", "*.go", false},
		{"double star", "/proj/a/b/c/file.go", "**/*.go", true},
		{"question mark", "/proj/a.go", "?.go", true},

		// Edge cases
		{"empty path", "", ".env", false},
		{"root path", "/", "/*", true}, // **/* matches / in doublestar
	}

	env := setupTestEnv(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := evalGlob(t, env, tc.path, tc.pattern)
			assert.Equal(t, tc.want, result)
		})
	}
}

func TestGlobInvalidPattern(t *testing.T) {
	env := setupTestEnv(t)

	// Invalid pattern should cause an error
	ast, iss := env.Compile(`"/proj/.env".glob("[invalid")`)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	_, _, err = prg.Eval(map[string]any{})
	assert.Error(t, err, "invalid pattern should cause eval error")
}

func TestUnderFunction(t *testing.T) {
	tests := []struct {
		name string
		path string
		dir  string
		want bool
	}{
		// Basic cases
		{"exact match", "/proj", "/proj", true},
		{"under dir", "/proj/src/file.go", "/proj", true},
		{"not under", "/other/file.go", "/proj", false},

		// Edge cases with empty dir
		{"empty dir guard", "/proj/file.go", "", false},
		{"empty path empty dir", "", "", false},

		// Root dir special case
		{"root matches absolute", "/proj/file.go", "/", true},
		{"root matches root", "/", "/", true},
		{"root no match relative", "proj/file.go", "/", false},

		// Sibling prevention (ensure /projx doesn't match /proj)
		{"sibling no match", "/projx/file.go", "/proj", false},
		{"similar prefix no match", "/project/file.go", "/proj", false},

		// Nested directories
		{"deeply nested", "/a/b/c/d/e/f.txt", "/a/b", true},
		{"parent not under child", "/proj", "/proj/src", false},
	}

	env := setupTestEnv(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := evalUnder(t, env, tc.path, tc.dir)
			assert.Equal(t, tc.want, result)
		})
	}
}

func TestInTmpFunction(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// /tmp
		{"tmp root", "/tmp", true},
		{"tmp nested", "/tmp/file.txt", true},
		{"tmp deep", "/tmp/a/b/c/file.txt", true},

		// /var/tmp
		{"var tmp root", "/var/tmp", true},
		{"var tmp nested", "/var/tmp/file.txt", true},

		// macOS /private/tmp
		{"private tmp root", "/private/tmp", true},
		{"private tmp nested", "/private/tmp/file.txt", true},

		// macOS /private/var/folders
		{"private var folders root", "/private/var/folders", true},
		{"private var folders nested", "/private/var/folders/xx/yy/T/file", true},

		// Non-tmp paths
		{"home", "/home/user", false},
		{"proj", "/proj/file.go", false},
		{"etc", "/etc/passwd", false},

		// Edge cases: similar but not tmp
		{"tmpx no match", "/tmpx/file.txt", false},
		{"var tmpx no match", "/var/tmpx/file.txt", false},
	}

	env := setupTestEnv(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := evalInTmp(t, env, tc.path)
			assert.Equal(t, tc.want, result)
		})
	}
}

func TestFunctionsInPolicyContext(t *testing.T) {
	// Test that the functions work correctly in a policy rule context
	tests := []struct {
		name string
		when string
		vars map[string]any
		want bool
	}{
		{
			name: "glob with reads variable",
			when: `reads.exists(p, p.glob(".env"))`,
			vars: map[string]any{
				"reads": []string{"/proj/.env", "/proj/src/main.go"},
			},
			want: true,
		},
		{
			name: "under with cwd",
			when: `writes.all(p, p.under(cwd) || p.in_tmp())`,
			vars: map[string]any{
				"writes": []string{"/proj/out.txt", "/tmp/cache"},
				"cwd":    "/proj",
			},
			want: true,
		},
		{
			name: "under outside cwd",
			when: `writes.exists(p, !p.under(cwd) && !p.in_tmp())`,
			vars: map[string]any{
				"writes": []string{"/etc/passwd"},
				"cwd":    "/proj",
			},
			want: true,
		},
		{
			name: "combined functions",
			when: `accesses.exists(p, p.glob("{.env,.env.*}") && !p.in_tmp())`,
			vars: map[string]any{
				"accesses": []string{"/proj/.env.local"},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			ast, iss := env.Compile(tc.when)
			require.NoError(t, iss.Err(), "compile error")

			prg, err := env.Program(ast)
			require.NoError(t, err, "program error")

			out, _, err := prg.Eval(tc.vars)
			require.NoError(t, err, "eval error")

			got, ok := out.Value().(bool)
			require.True(t, ok, "result should be bool")
			assert.Equal(t, tc.want, got)
		})
	}
}

// setupTestEnv creates a CEL environment with the custom functions and test variables
func setupTestEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := Env()
	require.NoError(t, err)
	// Extend with test variables
	env, err = env.Extend(
		cel.Variable("p", cel.StringType),
		cel.Variable("pattern", cel.StringType),
		cel.Variable("dir", cel.StringType),
	)
	require.NoError(t, err)
	return env
}

func evalGlob(t *testing.T, env *cel.Env, path, pattern string) bool {
	t.Helper()
	expr := `p.glob(pattern)`
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{
		"p":       path,
		"pattern": pattern,
	})
	require.NoError(t, err)
	return out.Value().(bool)
}

func evalUnder(t *testing.T, env *cel.Env, path, dir string) bool {
	t.Helper()
	expr := `p.under(dir)`
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{
		"p":   path,
		"dir": dir,
	})
	require.NoError(t, err)
	return out.Value().(bool)
}

func evalInTmp(t *testing.T, env *cel.Env, path string) bool {
	t.Helper()
	expr := `p.in_tmp()`
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err())

	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{
		"p": path,
	})
	require.NoError(t, err)
	return out.Value().(bool)
}
