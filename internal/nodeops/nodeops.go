// Package nodeops installs, updates, removes and switches Node.js versions
// on apt hosts. Side installs are nodejs.org's official linux tarballs under
// /opt/node/NN, verified against the Node.js release keys compiled into the
// agent; the host default is NodeSource's nodejs package at /usr/bin/node.
// Every operation runs as root through sudo and makes its checks at
// execution time.
package nodeops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

const (
	// InstallRoot holds one directory per side-installed major.
	InstallRoot = "/opt/node"
	// DefaultNode is NodeSource's node.
	DefaultNode = "/usr/bin/node"
	// DistURL is where nodejs.org publishes releases.
	DistURL = "https://nodejs.org/dist"

	removeBackupRoot  = "/var/backups/node-remove"
	switchBackupRoot  = "/var/backups/node-switch"
	defaultBackupRoot = "/var/backups/node-default"
	stampLayout       = "20060102T150405Z"
	settleTime        = 10 * time.Second
)

var (
	majorRe   = regexp.MustCompile(`^[0-9]{2}$`)
	versionRe = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)$`)
	// BinaryRe is the node binaries switch_site moves sites between.
	BinaryRe = regexp.MustCompile(`^(/usr/bin/node|/opt/node/[0-9]{2}/bin/node|/home/[A-Za-z0-9._-]+/\.nvm/versions/node/v[0-9]+\.[0-9]+\.[0-9]+/bin/node)$`)
	// nodeBinDirRe matches a bin directory holding a node this package
	// knows: a side install or an nvm version.
	nodeBinDirRe  = regexp.MustCompile(`^(/opt/node/[0-9]{2}/bin|/home/[A-Za-z0-9._-]+/\.nvm/versions/node/v[0-9]+\.[0-9]+\.[0-9]+/bin)$`)
	programNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	unitNameRe    = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.service$`)
	programHeadRe = regexp.MustCompile(`^\s*\[program:([^\]]+)\]\s*$`)
	sectionHeadRe = regexp.MustCompile(`^\s*\[`)

	aptEnv = []string{"DEBIAN_FRONTEND=noninteractive"}
)

// Env holds what the operations need; tests replace all of it.
type Env struct {
	Runner runner.Runner
	// Root prefixes every host path (tests).
	Root string
	Now  func() time.Time
	Out  io.Writer
	// DistURL replaces nodejs.org's dist URL (tests).
	DistURL string
	// Client fetches releases; nil means a client with a 15 minute limit.
	Client *http.Client
	// Arch replaces runtime.GOARCH (tests).
	Arch string
	// Sleep waits before the health checks; nil sleeps (tests skip it).
	Sleep func(context.Context, time.Duration) error
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) host(p string) string {
	if e.Root == "" {
		return p
	}
	return strings.TrimPrefix(p, e.Root)
}

func (e *Env) say(format string, a ...any) { fmt.Fprintf(e.Out, format+"\n", a...) }

func (e *Env) distURL() string {
	if e.DistURL != "" {
		return strings.TrimSuffix(e.DistURL, "/")
	}
	return DistURL
}

func (e *Env) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 15 * time.Minute}
}

func (e *Env) arch() string {
	if e.Arch != "" {
		return e.Arch
	}
	return runtime.GOARCH
}

func (e *Env) sleep(ctx context.Context, d time.Duration) error {
	if e.Sleep != nil {
		return e.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (e *Env) run(ctx context.Context, env []string, argv ...string) (stdout, stderr string, code int, err error) {
	var out, errOut strings.Builder
	code, err = e.Runner.Run(ctx, runner.Command{Argv: argv, Env: env, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return "", "", code, fmt.Errorf("%s: %w", argv[0], err)
	}
	return out.String(), errOut.String(), code, nil
}

// check runs argv and fails unless it exits 0.
func (e *Env) check(ctx context.Context, what string, env []string, argv ...string) error {
	_, stderr, code, err := e.run(ctx, env, argv...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s failed with status %d:\n%s", what, code, tail(stderr))
	}
	return nil
}

// stream runs argv with its output going to Out, as apt's does.
func (e *Env) stream(ctx context.Context, what string, argv ...string) error {
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: aptEnv, Stdout: e.Out, Stderr: e.Out})
	if err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	if code != 0 {
		return fmt.Errorf("%s exited with status %d", what, code)
	}
	return nil
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, "\n")
}

func (e *Env) checkHost() error {
	if pm := (&state.Env{Root: e.Root}).DetectPackageManager(); pm != catalog.PackageManagerApt {
		return errors.New("refused: Node.js operations are only supported on apt hosts")
	}
	return nil
}

func checkMajor(major string) error {
	if !majorRe.MatchString(major) || major == "00" || major[0] == '0' {
		return fmt.Errorf("bad Node.js major %q: two digits, such as 22", major)
	}
	return nil
}

func installDir(major string) string { return InstallRoot + "/" + major }

// nodeVersion runs a node binary's --version and returns X.Y.Z.
func (e *Env) nodeVersion(ctx context.Context, bin string) (string, error) {
	out, stderr, code, err := e.run(ctx, nil, bin, "--version")
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out)
	if code != 0 || !versionRe.MatchString(v) {
		return "", fmt.Errorf("%s --version exited with status %d and printed %q: %s", e.host(bin), code, v, tail(stderr))
	}
	return strings.TrimPrefix(v, "v"), nil
}

func majorOf(version string) string {
	m, _, _ := strings.Cut(version, ".")
	return m
}

var headerDefineRe = regexp.MustCompile(`^#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+([0-9]+)\s*$`)

// headerVersion reads X.Y.Z from an install's include/node/node_version.h,
// the way Heimdall does, without running anything.
func (e *Env) headerVersion(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "include/node/node_version.h"))
	if err != nil {
		return "", err
	}
	parts := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if m := headerDefineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if _, seen := parts[m[1]]; !seen {
				parts[m[1]] = m[2]
			}
		}
	}
	if parts["MAJOR"] == "" || parts["MINOR"] == "" || parts["PATCH"] == "" {
		return "", fmt.Errorf("%s/include/node/node_version.h has no version", e.host(dir))
	}
	return parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["PATCH"], nil
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";")
}

// Token matching. A binary is a token: what comes before it is the start
// of the line or a separator, and what follows is the end or a separator.
const (
	afterDelims      = " \t;&|\"')`"
	beforeDelims     = " \t;&|\"'=(`"
	beforePathDelims = beforeDelims + "-@!+:" // systemd's ExecStart prefixes
)

// tokenAt lists where needle appears as a token in line.
func tokenAt(line, needle string, before string) []int {
	var out []int
	for i := 0; i <= len(line)-len(needle); {
		j := strings.Index(line[i:], needle)
		if j < 0 {
			break
		}
		at := i + j
		end := at + len(needle)
		okBefore := at == 0 || strings.IndexByte(before, line[at-1]) >= 0
		okAfter := end == len(line) || strings.IndexByte(afterDelims, line[end]) >= 0
		if okBefore && okAfter {
			out = append(out, at)
		}
		i = at + 1
	}
	return out
}

// replaceToken replaces needle where it is a token, returning the count.
func replaceToken(line, needle, with, before string) (string, int) {
	at := tokenAt(line, needle, before)
	for i := len(at) - 1; i >= 0; i-- {
		line = line[:at[i]] + with + line[at[i]+len(needle):]
	}
	return line, len(at)
}

// nodeToken matches node binaries in a line: an absolute path ending in
// /bin/node, or a bare node.
var nodePathRe = regexp.MustCompile(`/[A-Za-z0-9._/-]*/bin/node`)

// binaries lists the node binaries a line runs, in order: absolute paths
// as written, and "node" for a bare node.
func binaries(line string) []string {
	var out []string
	seen := map[string]bool{}
	for _, loc := range nodePathRe.FindAllStringIndex(line, -1) {
		p := line[loc[0]:loc[1]]
		if seen[p] {
			continue
		}
		if len(tokenAt(line, p, beforePathDelims)) > 0 {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(tokenAt(line, "node", beforeDelims)) > 0 {
		out = append(out, "node")
	}
	return out
}

// pathValueRe finds a PATH= assignment's value in an environment line.
var pathValueRe = regexp.MustCompile(`(^|[\s,"'=])PATH=(["']?)([A-Za-z0-9._/:$~+@-]*)`)

// pathEntries returns the PATH directories an environment line sets.
func pathEntries(line string) []string {
	m := pathValueRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	return strings.Split(m[3], ":")
}

// rewritePath moves a PATH from fromDir to toDir. /usr/bin stays (other
// tools live there): toDir goes in front of it. Going back to /usr/bin
// drops fromDir when /usr/bin is already there.
func rewritePath(line, fromDir, toDir string) (string, bool) {
	loc := pathValueRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return line, false
	}
	entries := strings.Split(line[loc[6]:loc[7]], ":")
	has := func(d string) bool {
		for _, x := range entries {
			if x == d {
				return true
			}
		}
		return false
	}
	if !has(fromDir) {
		return line, false
	}
	var out []string
	switch {
	case fromDir == "/usr/bin":
		if has(toDir) {
			return line, false
		}
		for _, x := range entries {
			if x == fromDir {
				out = append(out, toDir)
			}
			out = append(out, x)
		}
	case has(toDir):
		for _, x := range entries {
			if x != fromDir {
				out = append(out, x)
			}
		}
	default:
		for _, x := range entries {
			if x == fromDir {
				x = toDir
			}
			out = append(out, x)
		}
	}
	return line[:loc[6]] + strings.Join(out, ":") + line[loc[7]:], true
}

// defaultPath is the PATH supervisord and systemd services get.
var defaultPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// cronPath is cron's default PATH.
var cronPath = []string{"/usr/bin", "/bin"}

// resolveBare says which node a bare node runs with these PATH entries:
// the first directory holding one. /bin is /usr/bin on current releases.
func (e *Env) resolveBare(entries []string) string {
	for _, d := range entries {
		if d == "/bin" {
			d = "/usr/bin"
		}
		if !strings.HasPrefix(d, "/") {
			continue
		}
		if info, err := os.Stat(e.path(d + "/node")); err == nil && !info.IsDir() {
			return d + "/node"
		}
	}
	return ""
}

// service is one supervisor program, systemd unit file (or drop-in) or
// cron file that may run node.
type service struct {
	kind  string // supervisor, systemd or cron
	path  string // host path
	real  string
	name  string // program or unit; empty for cron
	lines []string
	// first and last line of a supervisor program's section; the whole
	// file otherwise.
	start, end int
}

// cmdLine reports whether line i is one that runs a command.
func (s service) cmdLine(i int) bool {
	line := s.lines[i]
	if isComment(line) {
		return false
	}
	switch s.kind {
	case "cron":
		t := strings.TrimSpace(line)
		if t == "" {
			return false
		}
		// Environment assignments in a crontab aren't commands.
		if k, _, ok := strings.Cut(t, "="); ok && !strings.ContainsAny(k, " \t") {
			return false
		}
		return true
	case "supervisor":
		k := iniKey(line)
		return k == "command"
	case "systemd":
		k := iniKey(line)
		return strings.HasPrefix(k, "ExecStart") || k == "ExecReload" || k == "ExecStop" || strings.HasPrefix(k, "ExecStop")
	}
	return false
}

// envLine reports whether line i sets the environment.
func (s service) envLine(i int) bool {
	if isComment(s.lines[i]) {
		return false
	}
	k := iniKey(s.lines[i])
	return s.kind == "supervisor" && k == "environment" || s.kind == "systemd" && k == "Environment"
}

// dirLine reports whether line i sets the working directory.
func (s service) dirLine(i int) bool {
	if isComment(s.lines[i]) {
		return false
	}
	k := iniKey(s.lines[i])
	return s.kind == "supervisor" && k == "directory" || s.kind == "systemd" && k == "WorkingDirectory"
}

func iniKey(line string) string {
	k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok {
		return ""
	}
	k = strings.TrimSpace(k)
	if strings.ContainsAny(k, " \t") {
		return ""
	}
	return k
}

// pathDirs is the PATH a service's commands run with.
func (s service) pathDirs() []string {
	if p := s.ownPath(); p != nil {
		return p
	}
	if s.kind == "cron" {
		return cronPath
	}
	return defaultPath
}

// ownPath is the PATH a supervisor program or unit sets itself, or nil.
func (s service) ownPath() []string {
	if s.kind == "cron" {
		return nil
	}
	for i := s.start; i <= s.end; i++ {
		if s.envLine(i) {
			if p := pathEntries(s.lines[i]); p != nil {
				return p
			}
		}
	}
	return nil
}

// services reads every supervisor program, systemd service file and
// drop-in, and cron file.
func (e *Env) services() []service {
	var out []service
	for _, g := range []struct{ kind, glob string }{
		{"supervisor", "/etc/supervisor/conf.d/*.conf"},
		{"systemd", "/etc/systemd/system/*.service"},
		{"systemd", "/etc/systemd/system/*.service.d/*.conf"},
		{"cron", "/etc/crontab"},
		{"cron", "/etc/cron.d/*"},
		{"cron", "/var/spool/cron/crontabs/*"},
	} {
		paths, _ := filepath.Glob(e.path(g.glob))
		sort.Strings(paths)
		for _, p := range paths {
			info, err := os.Lstat(p)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			lines := strings.Split(string(b), "\n")
			base := service{kind: g.kind, path: e.host(p), real: p, lines: lines, start: 0, end: len(lines) - 1}
			switch g.kind {
			case "supervisor":
				out = append(out, supervisorPrograms(base)...)
			case "systemd":
				base.name = filepath.Base(p)
				if strings.HasSuffix(filepath.Dir(p), ".service.d") {
					base.name = strings.TrimSuffix(filepath.Base(filepath.Dir(p)), ".d")
				}
				out = append(out, base)
			default:
				out = append(out, base)
			}
		}
	}
	return out
}

func supervisorPrograms(f service) []service {
	var out []service
	cur := -1
	for i, line := range f.lines {
		if sectionHeadRe.MatchString(line) {
			cur = -1
			if m := programHeadRe.FindStringSubmatch(line); m != nil {
				s := f
				s.name, s.start, s.end = m[1], i, i
				out = append(out, s)
				cur = len(out) - 1
			}
			continue
		}
		if cur >= 0 {
			out[cur].end = i
		}
	}
	return out
}

// runs says whether s runs binary bin: a command names it, a bare node
// resolves to it, or (when viaPath) the PATH it sets names bin's
// directory, as for a program that runs npm.
func (e *Env) runs(s service, bin string, viaPath bool) bool {
	bare := ""
	for i := s.start; i <= s.end; i++ {
		if !s.cmdLine(i) {
			continue
		}
		if len(tokenAt(s.lines[i], bin, beforePathDelims)) > 0 {
			return true
		}
		if len(tokenAt(s.lines[i], "node", beforeDelims)) > 0 {
			if bare == "" {
				bare = e.resolveBare(s.pathDirs())
			}
			if bare == bin {
				return true
			}
		}
	}
	if viaPath {
		for _, d := range s.ownPath() {
			if d == filepath.Dir(bin) {
				return true
			}
		}
	}
	return false
}

// target is a supervisor program or systemd unit to restart and check.
type target struct {
	kind, name string
	restarts   string // systemd NRestarts after the restart
}

func (t target) String() string {
	if t.kind == "supervisor" {
		return "supervisor program " + t.name
	}
	return t.name
}

// targetsFor lists the supervisor programs and systemd units running bin
// now (viaPath: see runs).
func (e *Env) targetsFor(ctx context.Context, bin string, viaPath bool) ([]target, error) {
	var out []target
	for _, s := range e.services() {
		if s.kind == "cron" || !e.runs(s, bin, viaPath) {
			continue
		}
		if err := checkName(s); err != nil {
			return nil, err
		}
		out = appendTarget(out, target{kind: s.kind, name: s.name})
	}
	return e.running(ctx, out)
}

func appendTarget(list []target, t target) []target {
	for _, x := range list {
		if x.kind == t.kind && x.name == t.name {
			return list
		}
	}
	list = append(list, t)
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].kind+"\x00"+list[i].name < list[j].kind+"\x00"+list[j].name
	})
	return list
}

// running keeps the targets that are running now: a stopped program or
// unit is left stopped, so it isn't restarted or checked.
func (e *Env) running(ctx context.Context, targets []target) ([]target, error) {
	var out []target
	for _, t := range targets {
		switch t.kind {
		case "supervisor":
			out1, _, _, err := e.run(ctx, nil, "/usr/bin/supervisorctl", "status", t.name+":*")
			if err != nil {
				return nil, err
			}
			if strings.Contains(out1, "RUNNING") || strings.Contains(out1, "STARTING") || strings.Contains(out1, "BACKOFF") {
				out = append(out, t)
			} else {
				e.say("Leaving %s alone: it isn't running", t)
			}
		case "systemd":
			props, err := e.unitProps(ctx, t.name)
			if err != nil {
				return nil, err
			}
			switch props["ActiveState"] {
			case "active", "activating", "reloading":
				out = append(out, t)
			default:
				e.say("Leaving %s alone: it is %s", t, orUnknown(props["ActiveState"]))
			}
		}
	}
	return out, nil
}

func checkName(s service) error {
	switch s.kind {
	case "supervisor":
		if !programNameRe.MatchString(s.name) {
			return fmt.Errorf("refused: supervisor program %q in %s has a name this can't pass to supervisorctl safely", s.name, s.path)
		}
	case "systemd":
		if !unitNameRe.MatchString(s.name) {
			return fmt.Errorf("refused: unit %q (%s) has a name this can't pass to systemctl safely", s.name, s.path)
		}
	}
	return nil
}

// restart restarts every target and records each unit's NRestarts.
func (e *Env) restart(ctx context.Context, targets []target) error {
	var errs []error
	for i := range targets {
		t := &targets[i]
		switch t.kind {
		case "supervisor":
			if err := e.check(ctx, "restarting "+t.String(), nil, "/usr/bin/supervisorctl", "restart", t.name+":*"); err != nil {
				errs = append(errs, err)
			}
		case "systemd":
			if err := e.check(ctx, "restarting "+t.name, nil, "/usr/bin/systemctl", "restart", t.name); err != nil {
				errs = append(errs, err)
				continue
			}
			props, err := e.unitProps(ctx, t.name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			t.restarts = props["NRestarts"]
		}
		e.say("Restarted %s", t)
	}
	return errors.Join(errs...)
}

func (e *Env) unitProps(ctx context.Context, unit string) (map[string]string, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/systemctl", "show", unit, "-p", "ActiveState", "-p", "NRestarts")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("systemctl show %s failed with status %d: %s", unit, code, tail(stderr))
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props, nil
}

// healthy waits, then checks every program is RUNNING and every unit
// active without having restarted since.
func (e *Env) healthy(ctx context.Context, targets []target) error {
	if len(targets) == 0 {
		return nil
	}
	e.say("Waiting %s before checking %d program(s) and unit(s)", settleTime, len(targets))
	if err := e.sleep(ctx, settleTime); err != nil {
		return err
	}
	var bad []string
	for _, t := range targets {
		switch t.kind {
		case "supervisor":
			out, _, _, err := e.run(ctx, nil, "/usr/bin/supervisorctl", "status", t.name+":*")
			if err != nil {
				return err
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			ok := strings.TrimSpace(out) != ""
			for _, l := range lines {
				if f := strings.Fields(l); len(f) < 2 || f[1] != "RUNNING" {
					ok = false
				}
			}
			if !ok {
				bad = append(bad, fmt.Sprintf("%s isn't RUNNING: %s", t, strings.TrimSpace(out)))
			}
		case "systemd":
			props, err := e.unitProps(ctx, t.name)
			if err != nil {
				return err
			}
			if props["ActiveState"] != "active" {
				bad = append(bad, fmt.Sprintf("%s is %s", t.name, orUnknown(props["ActiveState"])))
			} else if t.restarts != "" && props["NRestarts"] != t.restarts {
				bad = append(bad, fmt.Sprintf("%s restarted %s time(s) since", t.name, restartsSince(t.restarts, props["NRestarts"])))
			}
		}
	}
	if len(bad) > 0 {
		return errors.New("health check failed:\n" + strings.Join(bad, "\n"))
	}
	e.say("Every program and unit is running")
	return nil
}

func restartsSince(before, after string) string {
	a, err1 := strconv.Atoi(before)
	b, err2 := strconv.Atoi(after)
	if err1 != nil || err2 != nil {
		return "?"
	}
	return strconv.Itoa(b - a)
}

func orUnknown(s string) string {
	if s == "" {
		return "in an unknown state"
	}
	return s
}
