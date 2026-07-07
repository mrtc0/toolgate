package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLetsUnmarshalYAML(t *testing.T) {
	yaml := `
version: 1
default: ask
lets:
  first: '"a"'
  second: '"b"'
  third: '"c"'
rules:
  - name: r
    action: deny
    when: "true"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0644))

	f, err := parseFile(path)
	require.NoError(t, err)

	// Verify order is preserved
	require.Len(t, f.Lets, 3)
	assert.Equal(t, "first", f.Lets[0].Name)
	assert.Equal(t, "second", f.Lets[1].Name)
	assert.Equal(t, "third", f.Lets[2].Name)
}

func TestValidateLetName(t *testing.T) {
	tests := []struct {
		name    string
		letName string
		prior   map[string]bool
		wantErr string
	}{
		{"valid identifier", "my_var", nil, ""},
		{"starts with underscore", "_private", nil, ""},
		{"starts with digit", "1bad", nil, "invalid identifier"},
		{"contains dash", "my-var", nil, "invalid identifier"},
		{"CEL reserved word", "true", nil, "CEL reserved word"},
		{"CEL reserved let", "let", nil, "CEL reserved word"},
		{"builtin agent", "agent", nil, "conflicts with built-in"},
		{"builtin cwd", "cwd", nil, "conflicts with built-in"},
		{"builtin reads", "reads", nil, "conflicts with built-in"},
		{"duplicate", "x", map[string]bool{"x": true}, "duplicate let name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prior := tt.prior
			if prior == nil {
				prior = map[string]bool{}
			}
			err := validateLetName(tt.letName, prior)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestParseFileRejectsInvalidLetName(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "reserved word in let",
			yaml: `
version: 1
default: ask
lets:
  true: '"x"'
rules:
  - name: r
    action: deny
    when: "true"
`,
			wantErr: "CEL reserved word",
		},
		{
			name: "builtin collision",
			yaml: `
version: 1
default: ask
lets:
  cwd: '"/some/path"'
rules:
  - name: r
    action: deny
    when: "true"
`,
			wantErr: "conflicts with built-in",
		},
		{
			name: "duplicate let",
			yaml: `
version: 1
default: ask
lets:
  x: '"a"'
  x: '"b"'
rules:
  - name: r
    action: deny
    when: "true"
`,
			wantErr: "duplicate let name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0644))

			_, err := parseFile(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadPreservesLets(t *testing.T) {
	dir := t.TempDir()

	userYAML := `
version: 1
default: ask
lets:
  user_let: '"user_value"'
rules:
  - name: user-rule
    action: allow
    when: user_let == "user_value"
`
	userPath := filepath.Join(dir, "user.yaml")
	require.NoError(t, os.WriteFile(userPath, []byte(userYAML), 0644))

	projYAML := `
version: 1
lets:
  proj_let: '"proj_value"'
rules:
  - name: proj-rule
    action: deny
    when: proj_let == "proj_value"
`
	projPath := filepath.Join(dir, "project.yaml")
	require.NoError(t, os.WriteFile(projPath, []byte(projYAML), 0644))

	p, err := Load(userPath, projPath)
	require.NoError(t, err)

	// User lets should be preserved
	require.Len(t, p.UserLets, 1)
	assert.Equal(t, "user_let", p.UserLets[0].Name)

	// Project lets should be preserved
	require.Len(t, p.ProjectLets, 1)
	assert.Equal(t, "proj_let", p.ProjectLets[0].Name)
}
