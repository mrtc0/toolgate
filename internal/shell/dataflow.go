package shell

import "strings"

// wrapper describes how to skip a wrapper command's own arguments to reach
// the wrapped command (e.g. `sudo -u root rm ...` -> `rm ...`).
type wrapper struct {
	valueFlags map[string]bool // short flags that consume the next argument
	skipEnv    bool            // skip leading VAR=VAL words (env)
	skipFirst  int             // positional args to skip (timeout DURATION)
}

var wrappers = map[string]wrapper{
	"command": {},
	"builtin": {},
	"exec":    {valueFlags: map[string]bool{"-a": true}},
	"nohup":   {},
	"time":    {},
	"nice":    {valueFlags: map[string]bool{"-n": true}},
	"stdbuf":  {valueFlags: map[string]bool{"-i": true, "-o": true, "-e": true}},
	"doas":    {valueFlags: map[string]bool{"-u": true}},
	"sudo":    {valueFlags: map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-r": true, "-t": true, "-C": true, "-D": true, "-R": true, "-T": true, "-U": true}},
	"env":     {skipEnv: true, valueFlags: map[string]bool{"-u": true, "-C": true, "-S": true}},
	"timeout": {skipFirst: 1, valueFlags: map[string]bool{"-k": true, "-s": true}},
	"xargs":   {valueFlags: map[string]bool{"-a": true, "-d": true, "-E": true, "-e": true, "-I": true, "-i": true, "-L": true, "-l": true, "-n": true, "-P": true, "-s": true}},
}

// unwrapOnce strips one level of wrapper command. Returns the inner tokens
// and whether an unwrap happened.
func unwrapOnce(toks []token) ([]token, bool) {
	if len(toks) < 2 {
		return toks, false
	}
	name := normalizeName(toks[0].text, toks[0].unknown)
	w, ok := wrappers[name]
	if !ok {
		return toks, false
	}
	i := 1
	skipPositional := w.skipFirst
	for i < len(toks) {
		t := toks[i].text
		switch {
		case t == "--":
			i++
			goto done
		case strings.HasPrefix(t, "--"):
			i++
		case strings.HasPrefix(t, "-") && len(t) > 1:
			if w.valueFlags[t] && i+1 < len(toks) {
				i += 2
			} else {
				i++
			}
		case w.skipEnv && strings.Contains(t, "="):
			i++
		case skipPositional > 0:
			skipPositional--
			i++
		default:
			goto done
		}
	}
done:
	if i >= len(toks) {
		return toks, false
	}
	return toks[i:], true
}

// commands whose non-flag arguments are treated as write targets.
var (
	writeAllArgs = map[string]bool{
		"tee": true, "truncate": true, "shred": true, "rm": true,
		"vi": true, "vim": true, "nvim": true, "nano": true, "emacs": true,
		"pico": true, "ed": true,
	}
	// last non-flag argument is the destination
	writeLastArg = map[string]bool{
		"cp": true, "mv": true, "install": true, "rsync": true, "ln": true,
	}
	// non-flag arguments are read; skipFirst skips a leading pattern/script
	readArgs = map[string]int{
		"cat": 0, "less": 0, "more": 0, "head": 0, "tail": 0, "tac": 0,
		"nl": 0, "od": 0, "xxd": 0, "hexdump": 0, "base64": 0, "base32": 0,
		"strings": 0, "wc": 0, "cut": 0, "sort": 0, "uniq": 0, "file": 0,
		"source": 0, ".": 0, "grep": 1, "egrep": 1, "fgrep": 1, "rg": 1,
		"awk": 1, "gawk": 1,
	}
)

// dataFlow returns the file paths a command may write to / read from based on
// its arguments (redirections are handled separately by the caller).
// Interpreter bodies like `python -c '...'` are out of scope.
func dataFlow(name string, args []token, cwd string) (writes, reads []string) {
	positional := positionalArgs(args)
	add := func(dst *[]string, toks ...token) {
		for _, t := range toks {
			if t.unknown {
				continue
			}
			if p := absPath(t.text, cwd); p != "" {
				*dst = append(*dst, p)
			}
		}
	}

	switch {
	case name == "dd":
		for _, t := range args {
			if t.unknown {
				continue
			}
			if v, ok := strings.CutPrefix(t.text, "of="); ok {
				add(&writes, token{text: v})
			} else if v, ok := strings.CutPrefix(t.text, "if="); ok {
				add(&reads, token{text: v})
			}
		}
	case name == "sed":
		if hasInPlace(args) && len(positional) > 1 {
			add(&writes, positional[1:]...) // first positional is the script
		} else if len(positional) > 1 {
			add(&reads, positional[1:]...)
		}
	case writeAllArgs[name]:
		add(&writes, positional...)
	case writeLastArg[name]:
		if len(positional) >= 2 {
			add(&writes, positional[len(positional)-1])
			add(&reads, positional[:len(positional)-1]...)
		}
	default:
		if skip, ok := readArgs[name]; ok {
			if len(positional) > skip {
				add(&reads, positional[skip:]...)
			}
		}
	}
	return writes, reads
}

func positionalArgs(args []token) []token {
	var out []token
	optsDone := false
	for _, t := range args {
		if !optsDone && t.text == "--" {
			optsDone = true
			continue
		}
		if !optsDone && strings.HasPrefix(t.text, "-") && len(t.text) > 1 && !t.unknown {
			continue
		}
		out = append(out, t)
	}
	return out
}

func hasInPlace(args []token) bool {
	for _, t := range args {
		if t.text == "--in-place" || strings.HasPrefix(t.text, "--in-place=") {
			return true
		}
		if strings.HasPrefix(t.text, "-") && !strings.HasPrefix(t.text, "--") &&
			strings.ContainsRune(t.text, 'i') {
			return true
		}
	}
	return false
}
