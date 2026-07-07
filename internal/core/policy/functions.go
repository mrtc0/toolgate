package policy

import (
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// customFunctions returns the CEL function options for the custom path functions:
//   - p.glob(pattern) -> bool
//   - p.under(dir) -> bool
//   - p.in_tmp() -> bool
func customFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("glob",
			cel.MemberOverload("string_glob_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(globFunc),
			),
		),
		cel.Function("under",
			cel.MemberOverload("string_under_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(underFunc),
			),
		),
		cel.Function("in_tmp",
			cel.MemberOverload("string_in_tmp",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(inTmpFunc),
			),
		),
	}
}

// globFunc implements p.glob(pattern).
// Uses doublestar.Match for glob matching. Patterns not starting with "/"
// are implicitly prefixed with "**/" to match at any depth.
// Supports brace expansion: "{.env,.env.*}" matches .env or .env.local etc.
// Returns an error for invalid patterns (which triggers degraded mode).
func globFunc(lhs, rhs ref.Val) ref.Val {
	p, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("glob: receiver must be a string")
	}
	pattern, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("glob: pattern must be a string")
	}

	// Normalize path separators for consistent matching
	p = filepath.ToSlash(p)

	// If pattern doesn't start with "/", prepend "**/" for matching at any depth
	if !strings.HasPrefix(pattern, "/") {
		pattern = "**/" + pattern
	}

	matched, err := doublestar.Match(pattern, p)
	if err != nil {
		return types.NewErr("glob: invalid pattern %q: %v", pattern, err)
	}
	return types.Bool(matched)
}

// underFunc implements p.under(dir).
// Returns true if p equals dir or p is a path under dir (has prefix dir + "/").
// Guard: if dir is empty, returns false (prevents accidental match-all).
// Special case: if dir is "/", returns true if p starts with "/" (all absolute paths).
func underFunc(lhs, rhs ref.Val) ref.Val {
	p, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("under: receiver must be a string")
	}
	dir, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("under: directory must be a string")
	}

	// Empty dir guard: never match
	if dir == "" {
		return types.Bool(false)
	}

	// Special case: "/" matches all absolute paths
	if dir == "/" {
		return types.Bool(strings.HasPrefix(p, "/"))
	}

	// Exact match or prefix match with trailing separator
	if p == dir || strings.HasPrefix(p, dir+"/") {
		return types.Bool(true)
	}
	return types.Bool(false)
}

// inTmpFunc implements p.in_tmp().
// Returns true if p is under any of the standard temporary directories:
//   - /tmp
//   - /var/tmp
//   - /private/tmp (macOS)
//   - /private/var/folders (macOS per-user temp)
func inTmpFunc(arg ref.Val) ref.Val {
	p, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("in_tmp: receiver must be a string")
	}

	tmpDirs := []string{
		"/tmp",
		"/var/tmp",
		"/private/tmp",
		"/private/var/folders",
	}

	for _, dir := range tmpDirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return types.Bool(true)
		}
	}
	return types.Bool(false)
}
