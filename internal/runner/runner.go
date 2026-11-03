// Package runner runs commands as argument lists, never through a shell.
// Everything that executes a program goes through the Runner interface so
// tests can substitute a fake.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Command is one program invocation.
type Command struct {
	Argv []string
	// Env is added to a minimal fixed environment (PATH, LANG, LC_ALL).
	Env    []string
	Stdout io.Writer
	Stderr io.Writer
}

// Runner runs a command and returns its exit code. err is non-nil only when
// the program could not be started or waited for; a non-zero exit is not an
// error.
type Runner interface {
	Run(ctx context.Context, c Command) (exitCode int, err error)
}

// BaseEnv is the environment every command starts from.
var BaseEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}

// Exec runs real programs with os/exec.
type Exec struct{}

// Run implements Runner.
func (Exec) Run(ctx context.Context, c Command) (int, error) {
	if len(c.Argv) == 0 {
		return -1, errors.New("runner: empty argv")
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = append(append([]string{}, BaseEnv...), c.Env...)
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// Output runs argv and returns stdout. A non-zero exit is returned as the
// exit code, with stderr in the error only when the program failed to start.
func Output(ctx context.Context, r Runner, argv ...string) (stdout string, exitCode int, err error) {
	var out, errb bytes.Buffer
	code, err := r.Run(ctx, Command{Argv: argv, Stdout: &out, Stderr: &errb})
	if err != nil {
		return "", code, fmt.Errorf("%s: %w", argv[0], err)
	}
	return out.String(), code, nil
}

// Response is a canned result for Fake.
type Response struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Fake is a Runner for tests. It answers by the space-joined argv, falling
// back to Default, and records every call.
type Fake struct {
	mu        sync.Mutex
	Responses map[string]Response
	// Queue holds responses served in order per argv before Responses.
	Queue   map[string][]Response
	Default *Response
	Calls   []Command
}

// Run implements Runner.
func (f *Fake) Run(_ context.Context, c Command) (int, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, Command{Argv: append([]string{}, c.Argv...), Env: append([]string{}, c.Env...)})
	key := strings.Join(c.Argv, " ")
	var resp Response
	found := false
	if q := f.Queue[key]; len(q) > 0 {
		resp, found = q[0], true
		f.Queue[key] = q[1:]
	} else if r, ok := f.Responses[key]; ok {
		resp, found = r, true
	} else if f.Default != nil {
		resp, found = *f.Default, true
	}
	f.mu.Unlock()
	if !found {
		return -1, fmt.Errorf("fake runner: unexpected command %q", key)
	}
	if resp.Err != nil {
		return -1, resp.Err
	}
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, resp.Stdout)
	}
	if c.Stderr != nil {
		_, _ = io.WriteString(c.Stderr, resp.Stderr)
	}
	return resp.ExitCode, nil
}

// Argvs returns the space-joined argv of every recorded call.
func (f *Fake) Argvs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.Calls))
	for i, c := range f.Calls {
		out[i] = strings.Join(c.Argv, " ")
	}
	return out
}
