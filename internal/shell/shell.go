// Package shell parses a shell command string into a flat list of command
// invocations. The flattening walks
// newlines, `;`/`&&`/`||` chains, pipelines, subshells, command/process
// substitutions and function bodies, and collects every *syntax.CallExpr as an
// independent "command that may run". This deliberately over-approximates
// (both sides of `A && B` are listed) to stay on the safe side.
package shell

// Redirect is a single redirection attached to a command invocation.
type Redirect struct {
	Op     string // ">", ">>", "<", ...
	Target string // best-effort literal target; "" if unresolvable
}

// Command is one flattened command invocation.
type Command struct {
	Name       string     // resolved executable name, "" if unknown
	CWD        string     // working directory this invocation runs in (cd-threaded)
	Args       []string   // arguments with quotes removed (best-effort)
	Flags      []string   // normalized flag set: -rf -> [r f], --force -> [force]
	Raw        string     // original text of the invocation
	Redirects  []Redirect // redirections attached to the statement
	WritesTo   []string   // absolute paths this command may write to
	ReadsFrom  []string   // absolute paths this command may read from
	ArgPaths   []string   // absolute paths extracted from positional args and --flag=value (for accesses)
	InPipe     bool       // part of a pipeline
	PipeFrom   []string   // names of all upstream commands in the pipeline
	HasUnknown bool       // name/args contain unresolved expansions
}

// Result is the outcome of flattening one command string.
type Result struct {
	Commands []Command
	ParseOK  bool
}
