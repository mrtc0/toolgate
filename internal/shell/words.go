package shell

import (
	"path/filepath"
	"strings"

	"github.com/mrtc0/toolgate/internal/pathnorm"
	"mvdan.cc/sh/v3/syntax"
)

// wordText returns the best-effort literal text of a word with quotes
// removed, and whether it contains unresolved expansions ($VAR, $(cmd), ...).
func wordText(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var sb strings.Builder
	unknown := false
	var visit func(parts []syntax.WordPart)
	visit = func(parts []syntax.WordPart) {
		for _, p := range parts {
			switch x := p.(type) {
			case *syntax.Lit:
				sb.WriteString(unescape(x.Value))
			case *syntax.SglQuoted:
				sb.WriteString(x.Value)
			case *syntax.DblQuoted:
				visit(x.Parts)
			default:
				// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob, ...
				unknown = true
			}
		}
	}
	visit(w.Parts)
	return sb.String(), unknown
}

// unescape removes backslash escapes from a literal (`\rm` -> `rm`).
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			if s[i] == '\n' {
				continue // line continuation
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// normalizeName reduces `/bin/rm`, `\rm` etc. to `rm`. Returns "" when
// the name cannot be resolved at all.
func normalizeName(text string, unknown bool) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	base := filepath.Base(text)
	if base == "." || base == string(filepath.Separator) {
		if unknown {
			return ""
		}
		return text
	}
	return base
}

// normalizeFlags turns `-rf`, `-r -f`, `--recursive --force` into a flat set
// like [r f recursive force]. Long flags keep their name without the value.
func normalizeFlags(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "--" {
			break
		}
		switch {
		case strings.HasPrefix(a, "--") && len(a) > 2:
			name := strings.TrimPrefix(a, "--")
			if i := strings.IndexByte(name, '='); i >= 0 {
				name = name[:i]
			}
			out = append(out, name)
		case strings.HasPrefix(a, "-") && len(a) > 1 && a[1] != '-':
			body := a[1:]
			if i := strings.IndexByte(body, '='); i >= 0 {
				body = body[:i]
			}
			for _, ch := range body {
				out = append(out, string(ch))
			}
		}
	}
	return dedupe(out)
}

// withResolved appends the symlink-resolved form of each path so that rules
// matching on writes_to / reads_from cannot be bypassed with a symlink
// (e.g. `ln -s /etc/hosts x && tee x`). Paths that do not exist or cannot be
// resolved are kept as-is.
func withResolved(paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	out := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		out = append(out, pathnorm.WithResolved(p)...)
	}
	return out
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// absPath is pathnorm.Normalize with two shell-redirect guards: a bare "-"
// (stdin/stdout) and pure file descriptors ("2" in `2>&1`) are not paths.
func absPath(p, cwd string) string {
	p = strings.TrimSpace(p)
	if p == "-" {
		return ""
	}
	if p != "" && strings.Trim(p, "0123456789") == "" { // fd like 2 in `2>&1`
		return ""
	}
	return pathnorm.Normalize(p, cwd)
}
