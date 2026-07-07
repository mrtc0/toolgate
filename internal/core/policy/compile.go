package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// CompiledLet pairs a let definition with its compiled CEL program.
type CompiledLet struct {
	Let     Let
	Program cel.Program
	Type    *cel.Type // inferred type from AST
	Err     error
}

// CompiledRule pairs a rule with its compiled CEL program. A rule that failed
// to compile has a nil Program and a non-nil Err (broken rules are
// reported and the evaluation degrades to the default, they never crash the
// whole hook).
type CompiledRule struct {
	Rule    Rule
	Program cel.Program
	Err     error
}

// Compiled is a policy with all rule expressions pre-compiled.
type Compiled struct {
	Default     string
	UserLets    []CompiledLet // compiled lets from user policy
	ProjectLets []CompiledLet // compiled lets from project policy
	Rules       []CompiledRule
	Warnings    []string
	// Broken is true when at least one rule or let failed to compile. In that case
	// `allow` outcomes are degraded to the default action, because the broken
	// rule might have been a stricter rule that would have matched first.
	Broken bool
}

// Env builds the CEL environment with the evaluation context.
func Env() (*cel.Env, error) {
	opts := []cel.EnvOption{
		ext.Strings(),
		cel.Variable("agent", cel.StringType),
		cel.Variable("kind", cel.StringType),
		cel.Variable("tool", cel.StringType),
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("cmd", cel.StringType),
		cel.Variable("paths", cel.ListType(cel.StringType)),
		cel.Variable("path", cel.StringType),
		cel.Variable("mcp", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("cwd", cel.StringType),
		cel.Variable("home", cel.StringType),
		cel.Variable("session_id", cel.StringType),
		cel.Variable("cmds", cel.ListType(cel.DynType)),
		cel.Variable("parse_ok", cel.BoolType),
		// Unified path variables (computed from kind + paths/cmds)
		cel.Variable("reads", cel.ListType(cel.StringType)),
		cel.Variable("writes", cel.ListType(cel.StringType)),
		cel.Variable("accesses", cel.ListType(cel.StringType)),
	}
	// Add custom functions: glob, under, in_tmp
	opts = append(opts, customFunctions()...)
	return cel.NewEnv(opts...)
}

// Compile type-checks and compiles every rule of the policy.
// Lets and rules are compiled with source-specific environments to prevent
// project lets from shadowing user lets (isolation for security).
func (p *Policy) Compile() (*Compiled, error) {
	baseEnv, err := Env()
	if err != nil {
		return nil, fmt.Errorf("cel environment: %w", err)
	}
	c := &Compiled{Default: p.Default, Warnings: p.Warnings}

	// Compile user lets, extending the environment after each successful let
	userEnv := baseEnv
	for _, l := range p.UserLets {
		cl := CompiledLet{Let: l}
		userEnv, cl = compileLet(userEnv, l)
		if cl.Err != nil {
			c.Broken = true
		}
		c.UserLets = append(c.UserLets, cl)
	}

	// Compile project lets starting from base env (isolated from user lets)
	projectEnv := baseEnv
	for _, l := range p.ProjectLets {
		cl := CompiledLet{Let: l}
		projectEnv, cl = compileLet(projectEnv, l)
		if cl.Err != nil {
			c.Broken = true
		}
		c.ProjectLets = append(c.ProjectLets, cl)
	}

	// Compile rules with appropriate environment based on source
	for _, r := range p.Rules {
		var env *cel.Env
		if r.Source == "project" {
			env = projectEnv
		} else {
			env = userEnv
		}
		cr := compileRule(env, r)
		if cr.Err != nil {
			c.Broken = true
		}
		c.Rules = append(c.Rules, cr)
	}
	return c, nil
}

// compileLet compiles a single let expression and returns the extended environment.
func compileLet(env *cel.Env, l Let) (*cel.Env, CompiledLet) {
	cl := CompiledLet{Let: l}
	ast, iss := env.Compile(l.Expr)
	if iss != nil && iss.Err() != nil {
		cl.Err = fmt.Errorf("let %q: %w", l.Name, iss.Err())
		return env, cl
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		cl.Err = fmt.Errorf("let %q: %w", l.Name, err)
		return env, cl
	}
	cl.Program = prg
	outType := ast.OutputType()
	cl.Type = outType

	// Extend environment with this let as a variable
	extEnv, err := env.Extend(cel.Variable(l.Name, outType))
	if err != nil {
		cl.Err = fmt.Errorf("let %q: failed to extend env: %w", l.Name, err)
		return env, cl
	}
	return extEnv, cl
}

// compileRule compiles a single rule.
func compileRule(env *cel.Env, r Rule) CompiledRule {
	cr := CompiledRule{Rule: r}
	ast, iss := env.Compile(r.When)
	if iss != nil && iss.Err() != nil {
		cr.Err = fmt.Errorf("rule %q: %w", r.Name, iss.Err())
		return cr
	}
	if ast.OutputType() != cel.BoolType {
		cr.Err = fmt.Errorf("rule %q: expression must evaluate to bool, got %s", r.Name, ast.OutputType())
		return cr
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		cr.Err = fmt.Errorf("rule %q: %w", r.Name, err)
		return cr
	}
	cr.Program = prg
	return cr
}
