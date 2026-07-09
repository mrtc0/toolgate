package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
	"github.com/mrtc0/toolgate/internal/core/event"
)

// TestSensitiveFileAccessDefaultPolicy loads defaults:sensitive-file-access
// with a default allow so scenarios assert exactly which accesses are gated.
func TestSensitiveFileAccessDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:sensitive-file-access
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, action, rule string
		ev                 *event.Event
	}{
		{"read-dotenv", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", ".env")},
		{"read-dotenv-local", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", ".env.local")},
		{"write-dotenv-prod", "ask", "ask-env", enginetest.FileInput("Write", "/proj", "", ".env.production")},
		{"read-nested-dotenv", "ask", "ask-env", enginetest.FileInput("Read", "/proj", "", "config/.env")},
		{"cat-dotenv", "ask", "ask-env", enginetest.BashInput("cat .env")},
		{"cp-dotenv", "ask", "ask-env", enginetest.BashInput("cp .env /tmp/steal")},

		// SSH / private keys. SSH keys are gated via the .ssh/** dir, not by
		// bare key names, and TLS keys via PEM/PKCS extensions (not *.key).
		{"read-ssh-dir", "ask", "ask-private-keys", enginetest.FileInput("Read", "/proj", "", "/home/u/.ssh/id_rsa")},
		{"read-ssh-ed25519", "ask", "ask-private-keys", enginetest.FileInput("Read", "/proj", "", "/home/u/.ssh/id_ed25519")},
		{"read-pem", "ask", "ask-private-keys", enginetest.FileInput("Read", "/proj", "", "certs/server.pem")},
		{"cat-p12", "ask", "ask-private-keys", enginetest.BashInput("cat bundle.p12")},

		// Cloud credentials
		{"read-aws-creds", "ask", "ask-cloud-credentials", enginetest.FileInput("Read", "/proj", "", "/home/u/.aws/credentials")},
		{"read-kubeconfig", "ask", "ask-cloud-credentials", enginetest.FileInput("Read", "/proj", "", ".kube/config")},
		{"read-gcloud", "ask", "ask-cloud-credentials", enginetest.FileInput("Read", "/proj", "", "/home/u/.config/gcloud/access_tokens.db")},

		// Tokens / auth configs
		{"read-netrc", "ask", "ask-auth-tokens", enginetest.FileInput("Read", "/proj", "", "/home/u/.netrc")},
		{"read-npmrc", "ask", "ask-auth-tokens", enginetest.FileInput("Read", "/proj", "", ".npmrc")},
		{"read-git-credentials", "ask", "ask-auth-tokens", enginetest.FileInput("Read", "/proj", "", ".git-credentials")},

		// GPG
		{"read-gnupg", "ask", "ask-gpg", enginetest.FileInput("Read", "/proj", "", "/home/u/.gnupg/secring.gpg")},

		{"read-plain-file", "allow", "default", enginetest.FileInput("Read", "/proj", "", "main.go")},
		{"read-envrc", "allow", "default", enginetest.FileInput("Read", "/proj", "", ".envrc")},
		{"read-environment", "allow", "default", enginetest.FileInput("Read", "/proj", "", "environment.yaml")},
		{"unrelated-cmd", "allow", "default", enginetest.BashInput("ls -la")},
		// Intentional non-matches: *.key is not gated (Keynote docs, TLS keys use
		// .pem here), a bare key name outside .ssh is not gated, and .aws/config
		// (non-secret profile config) is not gated.
		{"read-keynote", "allow", "default", enginetest.FileInput("Read", "/proj", "", "deck.key")},
		{"read-bare-id-rsa", "allow", "default", enginetest.FileInput("Read", "/proj", "", "backups/id_rsa")},
		{"read-aws-config", "allow", "default", enginetest.FileInput("Read", "/proj", "", "/home/u/.aws/config")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Evaluate(tc.ev, pol, engine.Options{})
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("got (%s, %s), want (%s, %s)", d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}
