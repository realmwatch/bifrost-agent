package main

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestEnrollKeyStdinNeedsAKeyAndExcludesKey(t *testing.T) {
	defer func(old io.Reader) { stdin = old }(stdin)

	stdin = strings.NewReader("\n")
	if code, _, errOut := runCLI("enroll", "--hub", "https://bifrost.example.com", "--key-stdin"); code != ExitUsage || !strings.Contains(errOut, "--key-stdin") {
		t.Fatalf("empty stdin key = %d %q", code, errOut)
	}

	stdin = strings.NewReader("bfe_x\n")
	if code, _, errOut := runCLI("enroll", "--hub", "https://bifrost.example.com", "--key", "bfe_y", "--key-stdin"); code != ExitUsage || !strings.Contains(errOut, "not both") {
		t.Fatalf("both = %d %q", code, errOut)
	}
}

func TestTrustedKeysCheck(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"v":1,"keys":[],"extra":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI("trusted-keys", "check", bad); code != ExitError || errOut == "" {
		t.Fatalf("bad keys = %d %q", code, errOut)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, testkit.TrustedKeysJSON(testkit.NewApprover("user:alex")), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI("trusted-keys", "check", good); code != ExitOK || !strings.Contains(out, "valid trusted keys file") {
		t.Fatalf("good keys = %d %q %q", code, out, errOut)
	}
	if code, _, _ := runCLI("trusted-keys", "check"); code != ExitUsage {
		t.Fatalf("no file = %d", code)
	}
	alex, sam := testkit.NewApprover("user:alex"), testkit.NewApprover("user:sam")
	set := filepath.Join(dir, "set.json")
	if err := os.WriteFile(set, testkit.KeySet(1, 2, alex, sam), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI("trusted-keys", "check", set); code != ExitOK || !strings.Contains(out, "serial: 1\n") ||
		!strings.Contains(out, "owners: user:alex, user:sam\n") || strings.Contains(out, "warning") {
		t.Fatalf("key set = %d %q %q", code, out, errOut)
	}

	// status: the anchor plus a stored update.
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"trusted_keys_path":"`+set+`","state_dir":"`+dir+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	next := testkit.KeySet(2, 1, alex, sam)
	data, _ := json.Marshal(testkit.Update(next, alex, sam))
	if err := os.MkdirAll(filepath.Join(dir, "keysets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keysets", "2.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI("trusted-keys", "status", "--config", cfg)
	for _, want := range []string{"serial: 2\n", "organization: " + testkit.OrganizationID + "\n", "update threshold: 1\n", "keys: 2 (2 passkeys)\n", "stored updates applied: 1\n"} {
		if code != ExitOK || !strings.Contains(out, want) {
			t.Fatalf("status = %d %q %q, want %q", code, out, errOut, want)
		}
	}
}
