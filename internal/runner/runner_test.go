package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExec(t *testing.T) {
	sh, err := exec.LookPath("printenv")
	if err != nil {
		t.Skip("printenv not available")
	}
	var out bytes.Buffer
	code, err := Exec{}.Run(context.Background(), Command{Argv: []string{sh, "LC_ALL", "EXTRA"}, Env: []string{"EXTRA=1"}, Stdout: &out})
	if err != nil || code != 0 || out.String() != "C\n1\n" {
		t.Fatalf("code = %d err = %v out = %q", code, err, out.String())
	}
	// printenv exits 1 for an unset variable: a non-zero exit is not an error.
	code, err = Exec{}.Run(context.Background(), Command{Argv: []string{sh, "BIFROST_UNSET"}})
	if err != nil || code != 1 {
		t.Fatalf("unset: code = %d err = %v", code, err)
	}
	if _, err := (Exec{}).Run(context.Background(), Command{Argv: []string{"/nonexistent/binary"}}); err == nil {
		t.Fatal("missing binary: no error")
	}
	if _, err := (Exec{}).Run(context.Background(), Command{}); err == nil {
		t.Fatal("empty argv: no error")
	}
}

// A program that outlives its context gets SIGTERM first, so it (or the
// command sudo started for it) can clean up and release its locks.
func TestExecStopsWithSIGTERMFirst(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	_, _ = Exec{}.Run(ctx, Command{Argv: []string{sh, "-c", `trap 'echo cleaned up; exit 0' TERM; echo started; while :; do sleep 0.05; done`}, Stdout: &out})
	if got := out.String(); got != "started\ncleaned up\n" {
		t.Fatalf("out = %q, want the TERM trap to run", got)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("took %s: SIGTERM wasn't sent at the deadline", took)
	}
}

func TestFake(t *testing.T) {
	f := &Fake{
		Responses: map[string]Response{"a b": {Stdout: "x", ExitCode: 2}},
		Queue:     map[string][]Response{"a b": {{Stdout: "first"}}},
	}
	out, code, err := Output(context.Background(), f, "a", "b")
	if err != nil || out != "first" || code != 0 {
		t.Fatalf("queued = %q %d %v", out, code, err)
	}
	out, code, _ = Output(context.Background(), f, "a", "b")
	if out != "x" || code != 2 {
		t.Fatalf("response = %q %d", out, code)
	}
	if _, _, err := Output(context.Background(), f, "c"); err == nil || !strings.Contains(err.Error(), "unexpected command") {
		t.Fatalf("unexpected = %v", err)
	}
	if got := f.Argvs(); len(got) != 3 {
		t.Fatalf("calls = %v", got)
	}
}
