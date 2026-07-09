package engine

import (
	"encoding/json"
	"os"
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
