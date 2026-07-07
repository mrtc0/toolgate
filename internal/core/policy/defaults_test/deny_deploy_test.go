package defaults_test

import (
	"testing"

	"github.com/mrtc0/toolgate/internal/core/engine"
	"github.com/mrtc0/toolgate/internal/core/engine/enginetest"
)

// TestDenyDeployDefaultPolicy loads defaults:deny-deploy with a default allow
// so scenarios assert exactly which commands are blocked.
func TestDenyDeployDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	path := enginetest.WritePolicy(t, dir, "user.yaml", `
version: 1
default: allow
include:
  - defaults:deny-deploy
`)
	pol := enginetest.LoadPolicy(t, path, "")

	cases := []struct {
		name, cmd, action, rule string
	}{
		{"vercel", "vercel deploy", "deny", "deny-deploy"},
		{"netlify", "netlify deploy --prod", "deny", "deny-deploy"},
		{"flyctl", "flyctl deploy", "deny", "deny-deploy"},
		{"fly", "fly deploy", "deny", "deny-deploy"},
		{"wrangler", "wrangler publish", "deny", "deny-deploy"},
		{"serverless", "serverless deploy", "deny", "deny-deploy"},
		{"sls", "sls deploy", "deny", "deny-deploy"},
		{"pulumi", "pulumi up", "deny", "deny-deploy"},
		{"heroku", "heroku releases", "deny", "deny-deploy"},

		{"terraform-apply", "terraform apply", "deny", "deny-deploy"},
		{"terraform-destroy", "terraform destroy", "deny", "deny-deploy"},
		{"terraform-plan", "terraform plan", "allow", "default"},

		{"kubectl-apply", "kubectl apply -f deploy.yaml", "deny", "deny-deploy"},
		{"kubectl-delete", "kubectl delete pod foo", "deny", "deny-deploy"},
		{"kubectl-drain", "kubectl drain node1", "deny", "deny-deploy"},
		{"kubectl-get", "kubectl get pods", "allow", "default"},

		{"docker-push", "docker push myimage:latest", "deny", "deny-deploy"},
		{"docker-build", "docker build .", "allow", "default"},

		{"unrelated", "ls -la", "allow", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Evaluate(enginetest.BashInput(tc.cmd), pol, engine.Options{})
			if d.Action != tc.action || d.Rule != tc.rule {
				t.Errorf("cmd %q: got (%s, %s), want (%s, %s)", tc.cmd, d.Action, d.Rule, tc.action, tc.rule)
			}
		})
	}
}
