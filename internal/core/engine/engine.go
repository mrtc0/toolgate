// Package engine evaluates a normalized event against the compiled policy.
// The engine is pure: adapters normalize agent
// payloads (including path normalization) into an event.Event before calling
// Evaluate, so the core performs no I/O.
package engine

import (
	"fmt"

	"github.com/mrtc0/toolgate/internal/core/event"
	"github.com/mrtc0/toolgate/internal/core/policy"
	"github.com/mrtc0/toolgate/internal/shell"
)

// MaxCommandLen is the input size limit: longer commands are not
// parsed and are routed to ask.
const MaxCommandLen = 64 * 1024

// RuleTrace records how one rule evaluated for `toolgate explain`.
type RuleTrace struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Source  string `json:"source"`
	Matched bool   `json:"matched"`
	Skipped bool   `json:"skipped,omitempty"` // not evaluated (after first match)
	Error   string `json:"error,omitempty"`
}

// Decision is the final verdict for one tool call.
type Decision struct {
	Action   string      `json:"action"`
	Rule     string      `json:"rule"`    // matched rule, "default", or "builtin:..."
	Message  string      `json:"message"` // reason shown to Claude Code
	Trace    []RuleTrace `json:"trace,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
}

// Options tweaks evaluation behavior.
type Options struct {
	// FailOpen (TOOLGATE_FAIL_OPEN=1) turns fail-closed fallbacks into allow.
	// Safety is significantly reduced; a warning is always recorded.
	FailOpen bool
}

// Evaluate runs the full decision flow.
func Evaluate(ev *event.Event, pol *policy.Compiled, opts Options) Decision {
	d := Decision{Warnings: append([]string(nil), pol.Warnings...)}

	cmdStr := ev.Cmd
	isExec := ev.Kind == event.KindExec

	oversize := len(cmdStr) > MaxCommandLen
	res := shell.Result{ParseOK: true}
	if isExec && !oversize {
		res = shell.Flatten(cmdStr, ev.CWD)
	}

	// 1. Input size limit.
	if oversize {
		d.Rule = "builtin:input-size-limit"
		if opts.FailOpen {
			d.Action = policy.ActionAllow
			d.Warnings = append(d.Warnings, "command exceeds size limit but TOOLGATE_FAIL_OPEN=1 is set")
		} else {
			d.Action = policy.ActionAsk
			d.Message = fmt.Sprintf("Command exceeds %d bytes and was not analyzed. Confirm.", MaxCommandLen)
		}
		return d
	}

	// 2. Evaluate lets and build source-specific activations.
	baseVars := celVars(ev, res)
	userVars, userDegraded := evalLets(pol.UserLets, baseVars, &d)
	projectVars, projectDegraded := evalLets(pol.ProjectLets, baseVars, &d)
	degraded := pol.Broken || userDegraded || projectDegraded

	// 3. Evaluate the user layer and the project layer independently, each
	// first-match-wins within its own layer. The stricter of the two decisions
	// wins (step 4), so a project policy can only tighten the outcome, never
	// loosen it below what the user policy decided. The user layer is authoritative.
	userMatch, projMatch := -1, -1
	for i, cr := range pol.Rules {
		isProject := cr.Rule.Source == "project"
		t := RuleTrace{Name: cr.Rule.Name, Action: cr.Rule.Action, Source: cr.Rule.Source}
		vars := userVars
		layerDone := userMatch >= 0
		if isProject {
			vars = projectVars
			layerDone = projMatch >= 0
		}
		switch {
		case layerDone:
			t.Skipped = true
		case cr.Err != nil:
			t.Error = cr.Err.Error()
			d.Warnings = append(d.Warnings, "broken rule skipped: "+cr.Err.Error())
		default:
			out, _, err := cr.Program.Eval(vars)
			if err != nil {
				t.Error = err.Error()
				d.Warnings = append(d.Warnings, fmt.Sprintf("rule %q evaluation error: %v", cr.Rule.Name, err))
				degraded = true
			} else if out == nil {
				t.Error = "no result"
				degraded = true
			} else if b, ok := out.Value().(bool); ok && b {
				t.Matched = true
				if isProject {
					projMatch = i
				} else {
					userMatch = i
				}
			}
		}
		d.Trace = append(d.Trace, t)
	}

	// The user layer always has a decision: its matched rule or the user default.
	userAction, userRule, userMsg := pol.UserDefault, "default", ""
	if userMatch >= 0 {
		r := pol.Rules[userMatch].Rule
		userAction, userRule, userMsg = r.Action, r.Name, r.Message
	}
	// The project layer contributes only if it has an opinion: a matched rule, or
	// an explicit project default. Otherwise it stays out of the way.
	projAction, projRule, projMsg := "", "", ""
	projHasOpinion := false
	if projMatch >= 0 {
		r := pol.Rules[projMatch].Rule
		projAction, projRule, projMsg, projHasOpinion = r.Action, r.Name, r.Message, true
	} else if pol.ProjectDefault != "" {
		projAction, projRule, projHasOpinion = pol.ProjectDefault, "default", true
	}

	// Stricter wins. The project only overrides when it is at least as strict as
	// the user decision, so it can tighten but never loosen. On a tie the
	// project's rule is reported since it is the tightening layer.
	d.Action, d.Rule, d.Message = userAction, userRule, userMsg
	if projHasOpinion && policy.Severity(projAction) >= policy.Severity(userAction) {
		d.Action, d.Rule, d.Message = projAction, projRule, projMsg
	}
	anyMatched := userMatch >= 0 || projMatch >= 0

	// 4. Degraded policy: a broken rule might have been a stricter rule
	// that would have matched first, so never let a degraded policy allow.
	if degraded && !opts.FailOpen && policy.Severity(d.Action) < policy.Severity(pol.Default) {
		d.Warnings = append(d.Warnings, fmt.Sprintf(
			"policy is degraded; decision %q downgraded to default %q", d.Action, pol.Default))
		d.Action = pol.Default
		if d.Message == "" {
			d.Message = "Policy is partially broken; falling back to the default action."
		}
	}

	// 5. Shell parse failure is fail-closed: never silently allow.
	// A matched deny (from a regex rule) stays deny; anything weaker becomes
	// ask unless an explicit ask rule already matched.
	if isExec && !res.ParseOK && !opts.FailOpen &&
		d.Action != policy.ActionDeny && (!anyMatched || d.Action == policy.ActionAllow) {
		d.Action = policy.ActionAsk
		d.Rule = "builtin:shell-parse-failed"
		d.Message = "Shell command could not be parsed; structural rules were skipped. Confirm."
	}

	return d
}

// evalLets evaluates compiled lets and returns an extended activation map.
// Each let is evaluated once per event, and its result is added to the map.
func evalLets(lets []policy.CompiledLet, baseVars map[string]any, d *Decision) (map[string]any, bool) {
	result := make(map[string]any, len(baseVars)+len(lets))
	for k, v := range baseVars {
		result[k] = v
	}
	degraded := false
	for _, cl := range lets {
		if cl.Err != nil {
			degraded = true
			continue
		}
		out, _, err := cl.Program.Eval(result)
		if err != nil {
			d.Warnings = append(d.Warnings, fmt.Sprintf("let %q evaluation error: %v", cl.Let.Name, err))
			degraded = true
			continue
		}
		// Use the raw ref.Val value; CEL's default type adapter handles it
		result[cl.Let.Name] = out.Value()
	}
	return result, degraded
}

// celVars builds the CEL evaluation context.
func celVars(ev *event.Event, res shell.Result) map[string]any {
	input := ev.Input
	if input == nil {
		input = map[string]any{}
	}
	paths := ev.Paths
	if paths == nil {
		paths = []string{}
	}
	first := ""
	if len(paths) > 0 {
		first = paths[0]
	}
	cmds := make([]map[string]any, 0, len(res.Commands))
	for _, c := range res.Commands {
		cmds = append(cmds, cmdToMap(c))
	}
	reads, writes, accesses := unifiedPaths(ev, res)
	return map[string]any{
		"agent":      string(ev.Agent),
		"kind":       string(ev.Kind),
		"tool":       ev.Tool,
		"input":      input,
		"cmd":        ev.Cmd,
		"paths":      paths,
		"path":       first,
		"mcp":        map[string]string{"server": ev.MCP.Server, "tool": ev.MCP.Tool},
		"cwd":        ev.CWD,
		"home":       ev.Home,
		"session_id": ev.SessionID,
		"cmds":       cmds,
		"parse_ok":   res.ParseOK,
		"reads":      reads,
		"writes":     writes,
		"accesses":   accesses,
	}
}

// unifiedPaths computes the unified reads/writes/accesses variables based on
// the event kind and shell parse result.
//
// | kind                    | reads               | writes             | accesses                              |
// |-------------------------|---------------------|--------------------| --------------------------------------|
// | file.read / file.search | paths               | []                 | paths                                 |
// | file.write              | []                  | paths              | paths                                 |
// | exec                    | ∪ cmds[].reads_from | ∪ cmds[].writes_to | reads ∪ writes ∪ (∪ cmds[].arg_paths) |
// | mcp / other             | []                  | []                 | []                                    |
func unifiedPaths(ev *event.Event, res shell.Result) (reads, writes, accesses []string) {
	paths := ev.Paths
	if paths == nil {
		paths = []string{}
	}

	switch ev.Kind {
	case event.KindFileRead, event.KindFileSearch:
		return paths, []string{}, paths
	case event.KindFileWrite:
		return []string{}, paths, paths
	case event.KindExec:
		// For exec, aggregate from all commands
		if !res.ParseOK {
			// Parse failed: return empty to trigger fail-closed via builtin rule
			return []string{}, []string{}, []string{}
		}
		seen := make(map[string]bool)
		for _, c := range res.Commands {
			for _, p := range c.ReadsFrom {
				if !seen[p] {
					seen[p] = true
					reads = append(reads, p)
				}
			}
		}
		for _, c := range res.Commands {
			for _, p := range c.WritesTo {
				if !seen[p] {
					seen[p] = true
					writes = append(writes, p)
				}
			}
		}
		// accesses = reads ∪ writes ∪ arg_paths
		seenAccess := make(map[string]bool)
		for _, p := range reads {
			if !seenAccess[p] {
				seenAccess[p] = true
				accesses = append(accesses, p)
			}
		}
		for _, p := range writes {
			if !seenAccess[p] {
				seenAccess[p] = true
				accesses = append(accesses, p)
			}
		}
		for _, c := range res.Commands {
			for _, p := range c.ArgPaths {
				if !seenAccess[p] {
					seenAccess[p] = true
					accesses = append(accesses, p)
				}
			}
		}
		if reads == nil {
			reads = []string{}
		}
		if writes == nil {
			writes = []string{}
		}
		if accesses == nil {
			accesses = []string{}
		}
		return reads, writes, accesses
	default:
		// mcp, other: empty
		return []string{}, []string{}, []string{}
	}
}

func cmdToMap(c shell.Command) map[string]any {
	redirects := make([]map[string]any, 0, len(c.Redirects))
	for _, r := range c.Redirects {
		redirects = append(redirects, map[string]any{"op": r.Op, "target": r.Target})
	}
	return map[string]any{
		"name":        c.Name,
		"args":        emptyIfNil(c.Args),
		"flags":       emptyIfNil(c.Flags),
		"raw":         c.Raw,
		"redirects":   redirects,
		"writes_to":   emptyIfNil(c.WritesTo),
		"reads_from":  emptyIfNil(c.ReadsFrom),
		"arg_paths":   emptyIfNil(c.ArgPaths),
		"in_pipe":     c.InPipe,
		"pipe_from":   emptyIfNil(c.PipeFrom),
		"has_unknown": c.HasUnknown,
	}
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
