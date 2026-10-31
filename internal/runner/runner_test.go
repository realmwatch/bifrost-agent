package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
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
