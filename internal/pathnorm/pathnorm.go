// Package pathnorm extracts and normalizes the file paths a tool call
// touches.
package pathnorm

import (
	"os"
	"path/filepath"
	"strings"
)

// Normalize expands ~ and environment variables, absolutizes relative to
// cwd, and cleans the path.
func Normalize(p, cwd string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) {
		if cwd == "" {
			return filepath.Clean(p)
		}
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// WithResolved returns p together with its symlink-resolved form when that
// differs. A path that cannot be resolved (missing, permission denied, ...)
// yields just p; an empty path yields nothing. This is the single place that
// decides "match both the symlink and its target" so policy rules cannot be
// bypassed with a symlink.
func WithResolved(p string) []string {
	if p == "" {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved != p {
		return []string{p, resolved}
	}
	return []string{p}
}

// StaticPrefix returns the leading directory part of a glob pattern that
// contains no metacharacters ("src/a/**/*.go" -> "src/a").
func StaticPrefix(pattern string) string {
	segs := strings.Split(filepath.ToSlash(pattern), "/")
	var keep []string
	for _, s := range segs {
		if strings.ContainsAny(s, "*?[{") {
			break
		}
		keep = append(keep, s)
	}
	// Drop the last segment: it is a file name, not a directory,
	// unless the pattern ended with a separator.
	if len(keep) == len(segs) && len(keep) > 0 && keep[len(keep)-1] != "" {
		keep = keep[:len(keep)-1]
	}
	return filepath.Join(keep...)
}
