package state

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

func writeFile(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

const livepatchStatusFixture = `{
  "client-version": "10.8.3",
  "status": [
    {"kernel": "6.8.0-40.40-generic", "running": false},
    {
      "kernel": "6.8.0-45.45-generic",
      "running": true,
      "livepatch": {"checkState": "checked", "patchState": "applied", "version": "105.1",
        "fixes": "* cve-2024-1086\n* cve-2024-26925 netfilter\n* cve-2024-1086"},
      "supported": "supported",
      "upgradeRequiredDate": "2025-10-01"
    }
  ]
}`

func TestLivepatchFacts(t *testing.T) {
	e := testEnv(t, "apt", &runner.Fake{})
	if lp := e.Facts().Livepatch; lp != nil {
		t.Fatalf("livepatch without /sys/kernel/livepatch = %+v", lp)
	}

	if err := os.MkdirAll(filepath.Join(e.Root, "sys/kernel/livepatch"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := e.Facts().Livepatch; !reflect.DeepEqual(got, &Livepatch{Patches: []string{}}) {
		t.Fatalf("supported, nothing loaded = %+v", got)
	}

	writeFile(t, e.Root, "sys/kernel/livepatch/lkp_Ubuntu_6_8_0_45_generic_105/enabled", "1\n")
	writeFile(t, e.Root, "sys/kernel/livepatch/lkp_Ubuntu_6_8_0_45_generic_105/transition", "1\n")
	if got := e.Facts().Livepatch; got.Applied {
		t.Fatalf("a patch mid-transition counts as applied: %+v", got)
	}
	writeFile(t, e.Root, "sys/kernel/livepatch/lkp_Ubuntu_6_8_0_45_generic_105/transition", "0\n")
	want := &Livepatch{Applied: true, Patches: []string{"lkp_Ubuntu_6_8_0_45_generic_105"}}
	if got := e.Facts().Livepatch; !reflect.DeepEqual(got, want) {
		t.Fatalf("applied = %+v", got)
	}
}

func TestBootReportsLivepatchClient(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		LivepatchClient + " status --format json": {Stdout: livepatchStatusFixture},
	}}
	e := testEnv(t, "apt", fake)
	writeFile(t, e.Root, "sys/kernel/livepatch/lkp_Ubuntu_6_8_0_45_generic_105/enabled", "1\n")

	res, err := e.RunTool(context.Background(), "boot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := asJSON(t, res); !strings.Contains(got, `"livepatch":{"applied":true,"client":null,"patches":["lkp_Ubuntu_6_8_0_45_generic_105"]}`) {
		t.Fatalf("without the client: %s", got)
	}

	writeFile(t, e.Root, LivepatchClient, "#!/bin/sh\n")
	got := e.LivepatchStatus(context.Background())
	want := &LivepatchStatus{PatchState: "applied", Version: "105.1", Fixes: []string{"CVE-2024-1086", "CVE-2024-26925"}, Support: "supported", UpgradeRequiredBy: "2025-10-01"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v", got)
	}

	fake.Responses[LivepatchClient+" status --format json"] = runner.Response{Stdout: "not json", ExitCode: 0}
	if got := e.LivepatchStatus(context.Background()); got.Error == "" {
		t.Fatalf("bad output gave no error: %+v", got)
	}
}
