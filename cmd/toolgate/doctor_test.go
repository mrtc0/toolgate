package main

import (
	"os"
	"path/filepath"
	"testing"
)

// setupDoctorEnv points XDG_CONFIG_HOME and HOME at temp dirs so doctor sees
// only what the test writes, and returns the toolgate config dir.
func setupDoctorEnv(t *testing.T) string {
	t.Helper()
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir()) // no agent hook configs: warnings only
	dir := filepath.Join(xdg, "toolgate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeDoctorFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const healthyPolicy = `
version: 1
default: ask
rules:
  - name: ok-rule
    action: allow
    when: "true"
`

func TestDoctorHealthy(t *testing.T) {
	dir := setupDoctorEnv(t)
	writeDoctorFile(t, filepath.Join(dir, "policy.yaml"), healthyPolicy)
	t.Chdir(t.TempDir()) // no project policy

	if code := runDoctor(); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// A let that fails to compile must fail doctor — previously a broken let left
// doctor silent (only rule errors were reported) and it exited 0.
func TestDoctorReportsBrokenLet(t *testing.T) {
	dir := setupDoctorEnv(t)
	writeDoctorFile(t, filepath.Join(dir, "policy.yaml"), `
version: 1
default: ask
lets:
  bad: "this is not CEL ((("
rules:
  - name: ok-rule
    action: allow
    when: "true"
`)
	t.Chdir(t.TempDir())

	if code := runDoctor(); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// Doctor checks the project policy found from the current directory, not just
// the user policy.
func TestDoctorReportsBrokenProjectPolicy(t *testing.T) {
	dir := setupDoctorEnv(t)
	writeDoctorFile(t, filepath.Join(dir, "policy.yaml"), healthyPolicy)

	proj := t.TempDir()
	writeDoctorFile(t, filepath.Join(proj, ".toolgate.yaml"), `
version: 1
rules:
  - name: broken-rule
    action: deny
    when: "this is not CEL ((("
`)
	t.Chdir(proj)

	if code := runDoctor(); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestDoctorHealthyProjectPolicy(t *testing.T) {
	dir := setupDoctorEnv(t)
	writeDoctorFile(t, filepath.Join(dir, "policy.yaml"), healthyPolicy)

	proj := t.TempDir()
	writeDoctorFile(t, filepath.Join(proj, ".toolgate.yaml"), `
version: 1
default: ask
rules:
  - name: proj-rule
    action: deny
    when: "false"
`)
	t.Chdir(proj)

	if code := runDoctor(); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}
