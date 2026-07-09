package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDefaultsPath(t *testing.T) {
	// Test embedded defaults
	path, data, err := resolveDefaultsPath("self-protection")
	if err != nil {
		t.Fatalf("resolveDefaultsPath(self-protection) error: %v", err)
	}
	if path != "embed://defaults/self-protection.yaml" {
		t.Errorf("expected embed:// path, got %s", path)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestResolveDefaultsPathNotFound(t *testing.T) {
	_, _, err := resolveDefaultsPath("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent defaults")
	}
}

func TestResolveIncludePathRelative(t *testing.T) {
	dir := t.TempDir()
	includedFile := filepath.Join(dir, "included.yaml")
	if err := os.WriteFile(includedFile, []byte("version: 1\ndefault: ask\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, data, err := resolveIncludePath("./included.yaml", dir)
	if err != nil {
		t.Fatalf("resolveIncludePath error: %v", err)
	}
	if path != includedFile {
		t.Errorf("expected %s, got %s", includedFile, path)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestResolveIncludePathAbsolute(t *testing.T) {
	dir := t.TempDir()
	includedFile := filepath.Join(dir, "absolute.yaml")
	if err := os.WriteFile(includedFile, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, data, err := resolveIncludePath(includedFile, "/some/other/dir")
	if err != nil {
		t.Fatalf("resolveIncludePath error: %v", err)
	}
	if path != includedFile {
		t.Errorf("expected %s, got %s", includedFile, path)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestLoadWithIncludesSimple(t *testing.T) {
	dir := t.TempDir()

	// Create included file
	includedFile := filepath.Join(dir, "base.yaml")
	includedContent := `
version: 1
lets:
  base_var: '"base_value"'
rules:
  - name: base-rule
    action: deny
    when: 'true'
    message: "base rule"
`
	if err := os.WriteFile(includedFile, []byte(includedContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create main file that includes base
	mainFile := filepath.Join(dir, "main.yaml")
	mainContent := `
version: 1
default: ask
include:
  - ./base.yaml
lets:
  main_var: '"main_value"'
rules:
  - name: main-rule
    action: allow
    when: 'false'
    message: "main rule"
`
	if err := os.WriteFile(mainFile, []byte(mainContent), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := parseFile(mainFile)
	if err != nil {
		t.Fatalf("parseFile error: %v", err)
	}

	// Check lets are merged (base first, then main)
	if len(f.Lets) != 2 {
		t.Errorf("expected 2 lets, got %d", len(f.Lets))
	}
	if f.Lets[0].Name != "base_var" {
		t.Errorf("expected base_var first, got %s", f.Lets[0].Name)
	}
	if f.Lets[1].Name != "main_var" {
		t.Errorf("expected main_var second, got %s", f.Lets[1].Name)
	}

	// Check rules are merged
	if len(f.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(f.Rules))
	}
	if f.Rules[0].Name != "base-rule" {
		t.Errorf("expected base-rule first, got %s", f.Rules[0].Name)
	}
	if f.Rules[1].Name != "main-rule" {
		t.Errorf("expected main-rule second, got %s", f.Rules[1].Name)
	}
}

func TestLoadWithIncludesCycleDetection(t *testing.T) {
	dir := t.TempDir()

	// Create file A that includes B
	fileA := filepath.Join(dir, "a.yaml")
	fileB := filepath.Join(dir, "b.yaml")

	contentA := `
version: 1
include:
  - ./b.yaml
rules:
  - name: rule-a
    action: deny
    when: 'true'
`
	contentB := `
version: 1
include:
  - ./a.yaml
rules:
  - name: rule-b
    action: deny
    when: 'true'
`
	if err := os.WriteFile(fileA, []byte(contentA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte(contentB), 0o644); err != nil {
		t.Fatal(err)
	}

	// Should not error due to cycle detection
	f, err := parseFile(fileA)
	if err != nil {
		t.Fatalf("parseFile error: %v", err)
	}

	// Should have rules from both files (cycle just means B's include of A is skipped)
	if len(f.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(f.Rules))
	}
}

func TestLoadWithIncludesEmbeddedDefaults(t *testing.T) {
	dir := t.TempDir()

	mainFile := filepath.Join(dir, "main.yaml")
	mainContent := `
version: 1
default: ask
include:
  - defaults:self-protection
rules:
  - name: custom-rule
    action: ask
    when: 'true'
`
	if err := os.WriteFile(mainFile, []byte(mainContent), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := parseFile(mainFile)
	if err != nil {
		t.Fatalf("parseFile error: %v", err)
	}

	// Should have self-protection rule + custom rule
	if len(f.Rules) < 2 {
		t.Errorf("expected at least 2 rules, got %d", len(f.Rules))
	}

	// First rule should be from self-protection
	if f.Rules[0].Name != "protect-gate-config" {
		t.Errorf("expected protect-gate-config first, got %s", f.Rules[0].Name)
	}
}

func TestListEmbeddedDefaults(t *testing.T) {
	names, err := ListEmbeddedDefaults()
	if err != nil {
		t.Fatalf("ListEmbeddedDefaults error: %v", err)
	}

	expected := map[string]bool{
		"self-protection":       true,
		"deny-publish":          true,
		"deny-deploy":           true,
		"allow-claude-code":     true,
		"sensitive-file-access": true,
		"dangerous-commands":    true,
		"shell-exec":            true,
		"interpreter-exec":      true,
		"git":                   true,
		"safe-cwd":              true,
		"recommended":           true,
	}

	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected default: %s", name)
		}
		delete(expected, name)
	}

	for name := range expected {
		t.Errorf("missing default: %s", name)
	}
}

func TestXDGOverrideDefaults(t *testing.T) {
	// Create temp XDG config
	xdgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdgDir)

	// Create override file
	defaultsDir := filepath.Join(xdgDir, "toolgate", "defaults")
	if err := os.MkdirAll(defaultsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	overrideContent := `
version: 1
rules:
  - name: overridden-rule
    action: deny
    when: 'true'
    message: "this is the override"
`
	overrideFile := filepath.Join(defaultsDir, "self-protection.yaml")
	if err := os.WriteFile(overrideFile, []byte(overrideContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Resolve should use XDG override
	path, _, err := resolveDefaultsPath("self-protection")
	if err != nil {
		t.Fatalf("resolveDefaultsPath error: %v", err)
	}
	if path != overrideFile {
		t.Errorf("expected XDG override path %s, got %s", overrideFile, path)
	}
}
