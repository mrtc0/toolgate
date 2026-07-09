package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultsPrefix = "defaults:"

// resolveIncludePath resolves an include path to an actual file path.
// Supports:
//   - "defaults:name" → XDG config or embedded defaults
//   - "./path" → relative to the including file
//   - "/path" → absolute path
func resolveIncludePath(includePath, baseDir string) (string, []byte, error) {
	if strings.HasPrefix(includePath, defaultsPrefix) {
		name := strings.TrimPrefix(includePath, defaultsPrefix)
		return resolveDefaultsPath(name)
	}

	// Relative or absolute path
	var resolved string
	if filepath.IsAbs(includePath) {
		resolved = includePath
	} else {
		resolved = filepath.Join(baseDir, includePath)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("include %q: %w", includePath, err)
	}
	return resolved, data, nil
}

// resolveDefaultsPath resolves a defaults:name include.
// Priority: XDG config > embedded defaults
func resolveDefaultsPath(name string) (string, []byte, error) {
	filename := name + ".yaml"

	// Try XDG config first
	xdgPath := xdgDefaultsPath(filename)
	if xdgPath != "" {
		if data, err := os.ReadFile(xdgPath); err == nil {
			return xdgPath, data, nil
		}
	}

	// Fall back to embedded defaults
	embeddedPath := "defaults/" + filename
	data, err := defaultsFS.ReadFile(embeddedPath)
	if err != nil {
		return "", nil, fmt.Errorf("defaults:%s not found", name)
	}
	return "embed://" + embeddedPath, data, nil
}

// xdgDefaultsPath returns the XDG config path for a defaults file.
func xdgDefaultsPath(filename string) string {
	configDir := ConfigDir()
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "defaults", filename)
}

// loadWithIncludes recursively loads a policy file and its includes.
// visited tracks already-loaded paths to prevent cycles.
func loadWithIncludes(path string, data []byte, visited map[string]bool) (*File, error) {
	if visited[path] {
		// Already loaded, skip to prevent cycles
		return &File{}, nil
	}
	visited[path] = true

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if f.Default != "" && !validActions(f.Default) {
		return nil, fmt.Errorf("%s: invalid default action %q", path, f.Default)
	}

	// Validate let names
	seen := make(map[string]bool)
	for _, l := range f.Lets {
		if err := validateLetName(l.Name, seen); err != nil {
			return nil, fmt.Errorf("%s: lets: %w", path, err)
		}
		seen[l.Name] = true
	}

	for i, r := range f.Rules {
		if r.When == "" {
			return nil, fmt.Errorf("%s: rule %q (#%d) has empty `when`", path, r.Name, i)
		}
		if !validActions(r.Action) {
			return nil, fmt.Errorf("%s: rule %q has invalid action %q", path, r.Name, r.Action)
		}
	}

	// Process includes
	if len(f.Include) == 0 {
		return &f, nil
	}

	baseDir := filepath.Dir(path)
	if strings.HasPrefix(path, "embed://") {
		baseDir = ""
	}

	merged := &File{
		Version: f.Version,
		Default: f.Default,
	}

	// This file's own rules come first: under first-match-wins the including
	// file overrides what it includes, so a policy can both loosen and tighten
	// the presets it pulls in.
	merged.Rules = append(merged.Rules, f.Rules...)

	includeDefault := ""
	for _, inc := range f.Include {
		incPath, incData, err := resolveIncludePath(inc, baseDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		incFile, err := loadWithIncludes(incPath, incData, visited)
		if err != nil {
			return nil, err
		}

		// Merge included file. Defaults from includes merge stricter-wins, so
		// include order cannot weaken the floor a stricter include declared.
		merged.Lets = append(merged.Lets, incFile.Lets...)
		merged.Rules = append(merged.Rules, incFile.Rules...)
		if incFile.Default != "" {
			if includeDefault == "" {
				includeDefault = incFile.Default
			} else {
				includeDefault = Stricter(includeDefault, incFile.Default)
			}
		}
	}
	// The including file's own explicit default wins over its includes'.
	if merged.Default == "" {
		merged.Default = includeDefault
	}

	// Lets keep include-first order (unlike rules): rules are compiled against
	// the environment after all lets are declared, so rule precedence is
	// unaffected, and this file's lets can reference the included presets'.
	merged.Lets = append(merged.Lets, f.Lets...)

	// Rules are evaluated against the single merged let list, so a name
	// collision across include boundaries would silently redefine a let that
	// an included rule depends on. Reject it like an in-file duplicate.
	seenLets := make(map[string]bool)
	for _, l := range merged.Lets {
		if seenLets[l.Name] {
			return nil, fmt.Errorf("%s: lets: duplicate let name %q across includes", path, l.Name)
		}
		seenLets[l.Name] = true
	}

	return merged, nil
}

// ListEmbeddedDefaults returns the names of all embedded default policies.
func ListEmbeddedDefaults() ([]string, error) {
	entries, err := defaultsFS.ReadDir("defaults")
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") {
			names = append(names, strings.TrimSuffix(name, ".yaml"))
		}
	}
	return names, nil
}
