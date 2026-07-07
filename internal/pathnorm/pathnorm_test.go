package pathnorm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name string
		in   string
		cwd  string
		want string
	}{
		{"empty", "", "/work", ""},
		{"absolute is cleaned", "/a/b/../c", "/work", "/a/c"},
		{"relative joined with cwd", "src/main.go", "/work", "/work/src/main.go"},
		{"dot resolved against cwd", ".", "/work", "/work"},
		{"parent traversal", "../sibling", "/work/app", "/work/sibling"},
		{"tilde expands to home", "~/notes.txt", "/work", filepath.Join(home, "notes.txt")},
		{"bare tilde expands to home", "~", "/work", home},
		{"relative without cwd stays clean", "a/b", "", "a/b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Normalize(tt.in, tt.cwd))
		})
	}
}

func TestNormalizeExpandsEnv(t *testing.T) {
	t.Setenv("MYDIR", "/expanded")
	assert.Equal(t, "/expanded/f", Normalize("$MYDIR/f", "/work"))
}

func TestWithResolved(t *testing.T) {
	t.Run("empty yields nothing", func(t *testing.T) {
		assert.Empty(t, WithResolved(""))
	})

	t.Run("plain path yields itself", func(t *testing.T) {
		dir := t.TempDir()
		resolvedDir, err := filepath.EvalSymlinks(dir)
		require.NoError(t, err)
		f := filepath.Join(resolvedDir, "real.txt")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
		assert.Equal(t, []string{f}, WithResolved(f))
	})

	t.Run("symlink yields both link and target", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.txt")
		require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
		link := filepath.Join(dir, "link.txt")
		require.NoError(t, os.Symlink(target, link))

		got := WithResolved(link)
		assert.Contains(t, got, link)
		resolved, err := filepath.EvalSymlinks(link)
		require.NoError(t, err)
		assert.Contains(t, got, resolved)
	})
}

func TestStaticPrefix(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"nested glob keeps static dirs", "src/a/**/*.go", filepath.Join("src", "a")},
		{"leading glob has no prefix", "**/*.go", ""},
		{"filename only dropped", "main.go", ""},
		{"dir with trailing slash kept", "src/pkg/", filepath.Join("src", "pkg")},
		{"single star segment stops", "src/*.ts", "src"},
		{"char class stops", "src/[abc]/x.go", "src"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, StaticPrefix(tt.pattern))
		})
	}
}
