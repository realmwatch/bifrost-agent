// Package state implements the read-only state tools the hub can query, and
// the facts the agent reports in its heartbeat.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/redact"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/schema"
)

// FSStat is the part of statfs the disk tool needs.
type FSStat struct {
	BlockSize   uint64
	Blocks      uint64
	BlocksFree  uint64
	BlocksAvail uint64
}

// Env is what the tools read from. Every path is under Root, so tests can
// point it at a fixture tree.
type Env struct {
	Runner runner.Runner
	// Root prefixes /etc and /proc paths ("" means the real root).
	Root string
	// Statfs reports filesystem usage for a mount point.
	Statfs func(path string) (FSStat, error)
	// Hostname returns the host name.
	Hostname func() (string, error)
	// PackageManager is "apt" or "dnf"; empty means unknown.
	PackageManager string
}

// NewEnv returns an Env for the real system.
func NewEnv(r runner.Runner, packageManager string) *Env {
	return &Env{Runner: r, Statfs: statfs, Hostname: os.Hostname, PackageManager: packageManager}
}

func statfs(path string) (FSStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return FSStat{}, err
	}
	return FSStat{BlockSize: uint64(s.Bsize), Blocks: s.Blocks, BlocksFree: s.Bfree, BlocksAvail: s.Bavail}, nil
}

// Path returns p under Root.
func (e *Env) Path(p string) string {
	if e.Root == "" {
		return p
	}
	return filepath.Join(e.Root, p)
}

func (e *Env) readFile(p string) (string, error) {
	b, err := os.ReadFile(e.Path(p))
	return string(b), err
}

// run runs a read-only command with TZ=UTC so timestamps parse as UTC.
func (e *Env) run(ctx context.Context, argv ...string) (stdout string, exitCode int, err error) {
	var out, errOut strings.Builder
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: []string{"TZ=UTC"}, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return "", code, fmt.Errorf("%s: %w", argv[0], err)
	}
	return out.String(), code, nil
}

// runOK is run that treats a non-zero exit as an error.
func (e *Env) runOK(ctx context.Context, argv ...string) (string, error) {
	out, code, err := e.run(ctx, argv...)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("%s exited with status %d", argv[0], code)
	}
	return out, nil
}

// Tool is one read-only state tool.
type Tool struct {
	Name string
	Args *schema.Schema
	Run  func(ctx context.Context, e *Env, args map[string]any) (any, error)
}

// unitPattern matches the units the status and journal tools accept.
const unitPattern = `^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,250}\\.(service|socket|timer|target|mount|path|slice|scope)$`

var tools = map[string]Tool{}

func register(name, argsSchema string, run func(context.Context, *Env, map[string]any) (any, error)) {
	s, err := schema.Compile([]byte(argsSchema))
	if err != nil {
		panic(fmt.Sprintf("state tool %s: %v", name, err))
	}
	tools[name] = Tool{Name: name, Args: s, Run: run}
}

const noArgs = `{"type":"object","additionalProperties":false,"properties":{}}`

func init() {
	register("os", noArgs, toolOS)
	register("packages", `{"type":"object","additionalProperties":false,"properties":{
		"names":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._+-]*$","maxLength":128}}}}`, toolPackages)
	register("pending_updates", noArgs, toolPendingUpdates)
	register("service_status", `{"type":"object","additionalProperties":false,"required":["unit"],"properties":{
		"unit":{"type":"string","pattern":"`+unitPattern+`","maxLength":256}}}`, toolServiceStatus)
	register("journal", `{"type":"object","additionalProperties":false,"required":["unit"],"properties":{
		"unit":{"type":"string","pattern":"`+unitPattern+`","maxLength":256},
		"lines":{"type":"integer","minimum":1,"maximum":500}}}`, toolJournal)
	register("disk", noArgs, toolDisk)
	register("memory", noArgs, toolMemory)
	register("ports", noArgs, toolPorts)
	register("sessions", noArgs, toolSessions)
}

// ToolNames lists the tools, sorted.
func ToolNames() []string {
	out := make([]string, 0, len(tools))
	for n := range tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RunTool validates args, runs the tool and redacts its result. The result
// is a JSON-ready value.
func (e *Env) RunTool(ctx context.Context, name string, args map[string]any) (any, error) {
	t, ok := tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	if args == nil {
		args = map[string]any{}
	}
	if err := t.Args.Validate(args); err != nil {
		return nil, fmt.Errorf("bad args: %w", err)
	}
	res, err := t.Run(ctx, e, args)
	if err != nil {
		return nil, err
	}
	// Round-trip through JSON so redaction sees plain maps and strings.
	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return redact.Value(generic), nil
}

var errNoPackageManager = errors.New("no supported package manager (apt or dnf) detected")

func (e *Env) requirePM() error {
	if e.PackageManager != catalog.PackageManagerApt && e.PackageManager != catalog.PackageManagerDnf {
		return errNoPackageManager
	}
	return nil
}

func intArg(args map[string]any, name string, def int) int {
	v, ok := args[name]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i)
		}
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}

func utcRFC3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
