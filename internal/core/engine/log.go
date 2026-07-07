package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrtc0/toolgate/internal/core/event"
)

// LogEntry is one decision-log record, written as JSON Lines.
type LogEntry struct {
	Time      string   `json:"time"`
	Agent     string   `json:"agent,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	Tool      string   `json:"tool"`
	Decision  string   `json:"decision"`
	Rule      string   `json:"matched_rule"`
	Cmd       string   `json:"cmd,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	DryRun    bool     `json:"dry_run,omitempty"`
	Message   string   `json:"message,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// WriteLog appends the decision to the TOOLGATE_LOG file. Failures are
// returned but must never change the decision.
func WriteLog(path string, ev *event.Event, d Decision, dryRun bool) error {
	entry := LogEntry{
		Time:      time.Now().Format(time.RFC3339),
		Agent:     string(ev.Agent),
		Kind:      string(ev.Kind),
		SessionID: ev.SessionID,
		Tool:      ev.Tool,
		Decision:  d.Action,
		Rule:      d.Rule,
		Cmd:       ev.Cmd,
		Paths:     ev.Paths,
		DryRun:    dryRun,
		Message:   d.Message,
		Warnings:  d.Warnings,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// SavedInput is the wrapper stored for `toolgate explain`: the agent name so
// explain knows which adapter to replay the raw payload through, plus the
// original stdin bytes.
type SavedInput struct {
	Agent string          `json:"agent"`
	Raw   json.RawMessage `json:"raw"`
}

// LastInputPath is where hook mode saves the most recent stdin payload so that
// `toolgate explain` can replay it.
func LastInputPath() string {
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "toolgate", "last-input.json")
}

// inputDir is the directory holding saved hook inputs.
func inputDir() string {
	p := LastInputPath()
	if p == "" {
		return ""
	}
	return filepath.Dir(p)
}

// sessionInputPath is where the input for a given session is saved. Distinct
// sessions get distinct files so concurrent sessions do not clobber each
// other's `toolgate explain` input.
func sessionInputPath(sessionID string) string {
	dir := inputDir()
	if dir == "" {
		return ""
	}
	if sessionID == "" {
		return LastInputPath()
	}
	return filepath.Join(dir, "last-input-"+sanitizeSession(sessionID)+".json")
}

// sanitizeSession keeps only filename-safe characters from a session id.
func sanitizeSession(id string) string {
	var sb strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	s := sb.String()
	if len(s) > 128 {
		s = s[:128]
	}
	if s == "" {
		return "session"
	}
	return s
}

// SaveLastInput stores the raw hook payload and its agent for later
// `toolgate explain`, keyed by session id. Best-effort.
func SaveLastInput(agent string, sessionID string, raw []byte) {
	p := sessionInputPath(sessionID)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(SavedInput{Agent: agent, Raw: json.RawMessage(raw)})
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o600)
}
