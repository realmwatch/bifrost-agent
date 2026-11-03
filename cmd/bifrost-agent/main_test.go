package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/testkit"
	"github.com/realmwatch/bifrost-agent/internal/verify"
	"github.com/realmwatch/bifrost-agent/internal/version"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCommands(t *testing.T) {
	if code, out, _ := runCLI("version"); code != 0 || strings.TrimSpace(out) != version.Version {
		t.Fatalf("version = %d %q", code, out)
	}
	if code, _, _ := runCLI(); code != ExitUsage {
		t.Fatalf("no args = %d", code)
	}
	if code, _, _ := runCLI("bogus"); code != ExitUsage {
		t.Fatalf("bogus = %d", code)
	}
	if code, _, _ := runCLI("enroll"); code != ExitUsage {
		t.Fatalf("enroll without flags = %d", code)
	}
	code, out, _ := runCLI("operations", "export")
	var doc map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc["catalog_version"] != version.Version {
		t.Fatalf("export = %d %q", code, out)
	}
	if code, out, _ := runCLI("operations", "sudoers", "--user", "agent"); code != 0 || !strings.Contains(out, "agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart *") {
		t.Fatalf("sudoers = %d %q", code, out)
	}
	if code, _, errOut := runCLI("state", "nope", "--config", "/nonexistent/config.json"); code != ExitError || !strings.Contains(errOut, "unknown tool") {
		t.Fatalf("state nope = %d %q", code, errOut)
	}
}

func TestParseArgs(t *testing.T) {
	got, err := parseArgs([]string{"unit=nginx.service", "lines=20", `names=["a","b"]`, "x=true"})
	if err != nil {
		t.Fatal(err)
	}
	if got["unit"] != "nginx.service" || got["lines"] != json.Number("20") || len(got["names"].([]any)) != 2 || got["x"] != true {
		t.Fatalf("args = %#v", got)
	}
	if _, err := parseArgs([]string{"novalue"}); err == nil {
		t.Fatal("missing = accepted")
	}
}

func TestVerifyCommand(t *testing.T) {
	dir := t.TempDir()
	a := testkit.NewApprover("user:alex")
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keys := write("trusted-keys.json", testkit.TrustedKeysJSON(a))
	cfg := write("config.json", []byte(`{"trusted_keys_path":"`+keys+`","state_dir":"`+dir+`","package_manager":"apt"}`))
	ops := []testkit.Step{{Op: "service.restart", Version: 1, Params: map[string]any{"unit": "nginx.service"}}}
	env := testkit.Envelope(ops, nil, "2999-01-01T00:00:00Z", 1)
	envFile := write("envelope.json", env)
	envB64 := write("envelope.b64", []byte(verify.B64U(env)+"\n"))
	approvals, _ := json.Marshal([]verify.Approval{a.Approve(env)})
	apprFile := write("approvals.json", approvals)

	for _, ef := range []string{envFile, envB64} {
		code, out, errOut := runCLI("verify", "--envelope", ef, "--approvals", apprFile, "--config", cfg, "--machine-id", testkit.MachineID)
		if code != 0 || !strings.Contains(out, `"ok": true`) || !strings.Contains(out, `"tier": "low"`) {
			t.Fatalf("verify %s = %d %s %s", ef, code, out, errOut)
		}
	}
	code, out, _ := runCLI("verify", "--envelope", envFile, "--approvals", apprFile, "--config", cfg, "--machine-id", "other")
	if code != ExitError || !strings.Contains(out, `"check": 2`) {
		t.Fatalf("wrong host = %d %s", code, out)
	}
	// verify never records the nonce.
	if _, err := os.Stat(filepath.Join(dir, "nonces.json")); err == nil {
		t.Fatal("verify wrote the nonce store")
	}
}
