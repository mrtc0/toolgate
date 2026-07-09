// Package policy loads, merges and compiles toolgate policies.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Actions, ordered by strictness: deny > ask > allow.
const (
	ActionAllow = "allow"
	ActionAsk   = "ask"
	ActionDeny  = "deny"
)

// Severity returns the strictness rank of an action.
func Severity(action string) int {
	switch action {
	case ActionDeny:
		return 2
	case ActionAsk:
		return 1
	default:
		return 0
	}
}

// Stricter returns the stricter of two actions.
func Stricter(a, b string) string {
	if Severity(a) >= Severity(b) {
		return a
	}
	return b
}

// Let is a named CEL expression for reuse in rules.
type Let struct {
	Name string
	Expr string
}

// Lets is an ordered list of Let definitions, parsed from a YAML map while
// preserving declaration order.
type Lets []Let

// UnmarshalYAML implements custom unmarshaling to preserve map key order.
func (l *Lets) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("lets must be a mapping, got %v", value.Kind)
	}
	result := make([]Let, 0, len(value.Content)/2)
	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("let name must be a string")
		}
		if valNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("let expression must be a string")
		}
		result = append(result, Let{Name: keyNode.Value, Expr: valNode.Value})
	}
	*l = result
	return nil
}

// Rule is one policy rule.
type Rule struct {
	Name    string `yaml:"name"`
	Action  string `yaml:"action"`
	When    string `yaml:"when"`
	Message string `yaml:"message"`
	// Source records which layer the rule came from ("user" / "project").
	Source string `yaml:"-"`
}

// File is a parsed policy YAML file.
type File struct {
	Version int      `yaml:"version"`
	Default string   `yaml:"default"`
	Include []string `yaml:"include"`
	Lets    Lets     `yaml:"lets"`
	Rules   []Rule   `yaml:"rules"`
}

// Policy is the merged, effective policy.
type Policy struct {
	// Default is the effective floor when no rule matches anywhere: the stricter
	// of the two layer defaults. Also the fallback a degraded policy falls back to.
	Default string
	// UserDefault is the user layer's own default (fallback when no user rule matches).
	UserDefault string
	// ProjectDefault is the project layer's own default, or "" when the project
	// policy declares none (the project layer then expresses no opinion).
	ProjectDefault string
	UserLets       []Let // lets from user policy (trusted)
	ProjectLets    []Let // lets from project policy (semi-trusted, isolated scope)
	Rules          []Rule
	// Warnings collected while loading.
	Warnings []string
}

func validActions(a string) bool {
	return a == ActionAllow || a == ActionAsk || a == ActionDeny
}

// identifierRe matches valid CEL/Go identifiers.
var identifierRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// celReservedWords are keywords reserved by CEL that cannot be used as let names.
var celReservedWords = map[string]bool{
	"true": true, "false": true, "null": true, "in": true, "as": true,
	"break": true, "const": true, "continue": true, "else": true,
	"for": true, "function": true, "if": true, "import": true, "let": true,
	"loop": true, "package": true, "namespace": true, "return": true,
	"var": true, "void": true, "while": true,
}

// builtinVars are the built-in CEL variables that cannot be shadowed by lets.
var builtinVars = map[string]bool{
	"agent": true, "kind": true, "tool": true, "input": true, "cmd": true,
	"paths": true, "path": true, "mcp": true, "cwd": true, "home": true,
	"toolgate_config_dir": true,
	"session_id":          true, "cmds": true, "parse_ok": true,
	"reads": true, "writes": true, "accesses": true,
}

// validateLetName checks if a name is valid for a let definition.
func validateLetName(name string, prior map[string]bool) error {
	if !identifierRe.MatchString(name) {
		return fmt.Errorf("invalid identifier %q", name)
	}
	if celReservedWords[name] {
		return fmt.Errorf("%q is a CEL reserved word", name)
	}
	if builtinVars[name] {
		return fmt.Errorf("%q conflicts with built-in variable", name)
	}
	if prior[name] {
		return fmt.Errorf("duplicate let name %q", name)
	}
	return nil
}

func parseFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	visited := make(map[string]bool)
	return loadWithIncludes(path, data, visited)
}

// ConfigDir returns toolgate's config directory, honoring XDG_CONFIG_HOME
// ($XDG_CONFIG_HOME/toolgate) and falling back to ~/.config/toolgate. It
// returns "" when neither can be resolved. This is the single source of truth
// for where the user policy and defaults overrides live, so self-protection can
// guard the directory regardless of XDG relocation.
func ConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "toolgate")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "toolgate")
}

// UserPolicyPath returns the path of the user (trusted) policy file.
func UserPolicyPath() string {
	dir := ConfigDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "policy.yaml")
}

// FindProjectPolicy walks up from cwd looking for a .toolgate.yaml.
func FindProjectPolicy(cwd string) string {
	dir := cwd
	for dir != "" {
		p := filepath.Join(dir, ".toolgate.yaml")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// Load reads and merges the user policy and the project policy.
//
// Merge semantics ("stricter wins"): the engine evaluates the user layer and the
// project layer independently and takes the stricter (deny > ask > allow) of the
// two decisions. A project policy can therefore only tighten the outcome, never
// loosen it below what the user policy decided. The user layer is authoritative.
// Project rules can tighten any decision; the project default participates only
// when no user rule matched, so a blanket project default cannot override
// explicit user allow rules.
func Load(userPath, projectPath string) (*Policy, error) {
	p := &Policy{Default: ActionAsk}

	var userFile, projFile *File
	if userPath != "" {
		if _, err := os.Stat(userPath); err == nil {
			f, err := parseFile(userPath)
			if err != nil {
				return nil, err
			}
			userFile = f
		}
	}
	if projectPath != "" {
		if _, err := os.Stat(projectPath); err == nil {
			f, err := parseFile(projectPath)
			if err != nil {
				return nil, err
			}
			projFile = f
		}
	}

	userDefault := ActionAsk
	if userFile != nil && userFile.Default != "" {
		userDefault = userFile.Default
	}
	p.UserDefault = userDefault
	if projFile != nil && projFile.Default != "" {
		p.ProjectDefault = projFile.Default
	}
	// Effective floor when no rule matches anywhere: the stricter of the two
	// layer defaults. An absent project default expresses no opinion.
	p.Default = userDefault
	if p.ProjectDefault != "" {
		p.Default = Stricter(userDefault, p.ProjectDefault)
	}

	if projFile != nil {
		p.ProjectLets = projFile.Lets
		for _, r := range projFile.Rules {
			r.Source = "project"
			p.Rules = append(p.Rules, r)
		}
	}
	if userFile != nil {
		p.UserLets = userFile.Lets
		for _, r := range userFile.Rules {
			r.Source = "user"
			p.Rules = append(p.Rules, r)
		}
	}
	return p, nil
}
