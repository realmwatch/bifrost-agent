package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	c, err := Load(write(t, `{"hub_url":"https://bifrost.example.com","simulate":true}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.PollIntervalSeconds != 5 || c.HeartbeatIntervalSeconds != 60 || c.StateDir != DefaultStateDir ||
		c.PackageManager != "auto" || !c.Sudo() || !c.Simulate {
		t.Fatalf("config = %+v", c)
	}
	if c, err := Load(write(t, `{"use_sudo":false}`), false); err != nil || c.Sudo() {
		t.Fatalf("use_sudo false: %+v, %v", c, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json"), true); err != nil {
		t.Fatalf("allowMissing: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json"), false); err == nil {
		t.Fatal("missing config accepted")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":  `{"hub":"x"}`,
		"http hub":       `{"hub_url":"http://bifrost.example.com"}`,
		"hub with query": `{"hub_url":"https://bifrost.example.com/?a=1"}`,
		"hub with creds": `{"hub_url":"https://a:b@bifrost.example.com"}`,
		"relative state": `{"state_dir":"state"}`,
		"poll zero":      `{"poll_interval_seconds":0}`,
		"heartbeat fast": `{"heartbeat_interval_seconds":1}`,
		"bad pm":         `{"package_manager":"zypper"}`,
		"not json":       `{`,
	}
	for name, doc := range cases {
		if _, err := Load(write(t, doc), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseHubURL("http://localhost:8000"); err != nil {
		t.Errorf("localhost http rejected: %v", err)
	}
}

func TestState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "state.json")
	if _, err := LoadState(p); err == nil {
		t.Fatal("missing state accepted")
	}
	s := State{HubURL: "https://bifrost.example.com", AgentID: "01JAGENT", ServerID: "01JSERVER", Token: "bfa_x"}
	if err := SaveState(p, s); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	got, err := LoadState(p)
	if err != nil || got != s {
		t.Fatalf("state = %+v, %v", got, err)
	}
}
