package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

const aptLockStderr = "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 900941 (apt-get)\nN: Be aware that removing the lock file is not a solution and may break your system.\nE: Unable to lock directory /var/lib/apt/lists/\n"

func refreshEnv(t *testing.T, update runner.Response) *Env {
	t.Helper()
	fake := &runner.Fake{Responses: map[string]runner.Response{
		"apt list --upgradable":      {Stdout: aptListFixture},
		"apt-mark showhold":          {Stdout: ""},
		"/usr/bin/apt-get -q update": update,
	}}
	e := testEnv(t, "apt", fake)
	write := func(p, content string) {
		t.Helper()
		full := e.Path(p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/proc/900941/cgroup", "0::/system.slice/MsftLinuxPatchAutoAssess.service\n")
	write("/var/lib/apt/lists/archive.example.com_ubuntu_dists_noble_InRelease", "")
	write("/var/lib/apt/lists/archive.example.com_ubuntu_dists_noble_main_binary-amd64_Packages", "")
	listed := time.Date(2026, 11, 11, 15, 20, 7, 0, time.UTC)
	if err := os.Chtimes(e.Path("/var/lib/apt/lists/archive.example.com_ubuntu_dists_noble_InRelease"), listed, listed); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRefreshSaysWhoHoldsAptsLock(t *testing.T) {
	e := refreshEnv(t, runner.Response{ExitCode: 100, Stderr: aptLockStderr})

	_, err := e.RunTool(context.Background(), "pending_updates", map[string]any{"refresh": true})

	want := "refreshing the package lists: apt is busy: another process (apt-get, PID 900941, from MsftLinuxPatchAutoAssess.service) holds /var/lib/apt/lists/lock"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v\nwant %s", err, want)
	}
}

func TestFallbackListsFromTheListsTheServerHas(t *testing.T) {
	e := refreshEnv(t, runner.Response{ExitCode: 100, Stderr: aptLockStderr})

	res, err := e.RunTool(context.Background(), "pending_updates", map[string]any{"refresh": true, "fallback": true})
	if err != nil {
		t.Fatal(err)
	}
	got := asJSON(t, res)
	for _, want := range []string{
		`"refresh":{"error":"refreshing the package lists: apt is busy`,
		`"lists_updated_at":"2026-11-11T15:20:07Z","ok":false,"requested":true}`,
		`"updates":[{`,
		`"security":true`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("result %s\ndoes not contain %s", got, want)
		}
	}
}

func TestFallbackAfterARefreshThatWorked(t *testing.T) {
	e := refreshEnv(t, runner.Response{Stdout: "Hit:1 http://archive.example.com noble InRelease\n"})

	res, err := e.RunTool(context.Background(), "pending_updates", map[string]any{"refresh": true, "fallback": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := asJSON(t, res); !strings.Contains(got, `"refresh":{"lists_updated_at":"2026-11-11T15:20:07Z","ok":true,"requested":true}`) {
		t.Fatalf("result %s", got)
	}

	// Without fallback the answer is the bare list, as older hubs expect.
	res, err = e.RunTool(context.Background(), "pending_updates", map[string]any{"refresh": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := asJSON(t, res); !strings.HasPrefix(got, `[{`) {
		t.Fatalf("result %s, want a list", got)
	}
}

func TestARefreshStoppedAtTheTimeLimitSaysSo(t *testing.T) {
	e := refreshEnv(t, runner.Response{ExitCode: -1})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err := e.RunTool(ctx, "pending_updates", map[string]any{"refresh": true})

	if err == nil || !strings.HasPrefix(err.Error(), "refreshing the package lists: apt-get took longer than ") || !strings.HasSuffix(err.Error(), " and was stopped") {
		t.Fatalf("err = %v", err)
	}
}

func TestCommandName(t *testing.T) {
	for argv, want := range map[string]string{
		"/usr/bin/sudo -n -- /usr/bin/apt-get -q update": "apt-get",
		"/usr/bin/apt-get -q update":                     "apt-get",
		"apt list --upgradable":                          "apt",
	} {
		if got := commandName(strings.Fields(argv)); got != want {
			t.Errorf("commandName(%q) = %q, want %q", argv, got, want)
		}
	}
}
