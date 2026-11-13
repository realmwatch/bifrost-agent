// Package kernelops purges old kernels on apt hosts. It runs as root through
// sudo for the removal (and as the agent's user for the check), deciding at
// execution time which of the listed kernels may go, because a report from
// earlier can't prove what is installed or running now.
package kernelops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/debversion"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

// MaxKernels is how many releases one call may name, as the operation's
// schema allows.
const MaxKernels = 50

var (
	// releaseRe is a kernel release as uname -r prints it, such as
	// 6.8.0-45-generic or 6.1.0-18-amd64. It is the schema's pattern.
	releaseRe = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?-[A-Za-z0-9.+~_-]+$`)

	aptEnv     = []string{"DEBIAN_FRONTEND=noninteractive"}
	aptOptions = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
)

// Env holds what the operation needs; tests replace all of it.
type Env struct {
	Runner runner.Runner
	Root   string
	Out    io.Writer
}

// pkg is one package dpkg knows, with its two-letter status (ii, hi, rc...).
type pkg struct{ Status, Name, Version string }

// plan is what Remove would do: the kernels it removes with their packages,
// and the listed kernels it leaves alone, with why.
type plan struct {
	running  string
	remove   []string
	packages []pkg
	skipped  []string
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) say(format string, a ...any) { fmt.Fprintf(e.Out, format+"\n", a...) }

func (e *Env) run(ctx context.Context, env []string, argv ...string) (stdout, stderr string, code int, err error) {
	var out, errOut strings.Builder
	code, err = e.Runner.Run(ctx, runner.Command{Argv: argv, Env: env, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return "", "", code, fmt.Errorf("%s: %w", argv[0], err)
	}
	return out.String(), errOut.String(), code, nil
}

// Check is the dry run: it decides what Remove would purge and simulates the
// purge, changing nothing.
func (e *Env) Check(ctx context.Context, releases []string) error {
	p, err := e.plan(ctx, releases)
	if err != nil {
		return err
	}
	e.say("Dry run: purging kernels %s would remove only their packages: %s", strings.Join(p.remove, ", "), strings.Join(names(p.packages), " "))
	return nil
}

// Remove purges the listed kernels that may go, then confirms with dpkg that
// they are gone and the running kernel is untouched.
func (e *Env) Remove(ctx context.Context, releases []string) error {
	p, err := e.plan(ctx, releases)
	if err != nil {
		return err
	}
	before, err := e.installed(ctx)
	if err != nil {
		return err
	}
	runningPkgs := kernelPackages(before, p.running)

	argv := append([]string{"/usr/bin/apt-get", "-q", "-y"}, aptOptions...)
	argv = append(append(argv, "purge"), names(p.packages)...)
	if err := e.stream(ctx, argv); err != nil {
		return fmt.Errorf("purge failed: %w", err)
	}

	after, err := e.installed(ctx)
	if err != nil {
		return fmt.Errorf("can't confirm the purge: %w", err)
	}
	now := map[string]pkg{}
	for _, q := range after {
		now[q.Name] = q
	}
	var left []string
	for _, q := range p.packages {
		if r, ok := now[q.Name]; ok && r.Status[1] != 'n' {
			left = append(left, q.Name)
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("packages are still installed after the purge: %s", strings.Join(left, ", "))
	}
	for _, q := range runningPkgs {
		if r, ok := now[q.Name]; !ok || r.Status != q.Status || r.Version != q.Version {
			return fmt.Errorf("the running kernel's package %s changed during the purge", q.Name)
		}
	}
	if _, err := os.Stat(e.path("/lib/modules/" + p.running)); err != nil {
		return fmt.Errorf("the running kernel's modules are missing after the purge: %w", err)
	}
	e.say("Removed kernels %s. Purged packages:", strings.Join(p.remove, ", "))
	for _, q := range p.packages {
		e.say("  %s %s", q.Name, q.Version)
	}
	e.say("The running kernel %s and its modules are untouched.", p.running)
	return nil
}

// plan validates the releases and decides, from what dpkg reports now, which
// kernels may go. It refuses when none may, or when purging their packages
// would remove or install anything else.
func (e *Env) plan(ctx context.Context, releases []string) (*plan, error) {
	releases, err := validate(releases)
	if err != nil {
		return nil, err
	}
	if pm := (&state.Env{Root: e.Root}).DetectPackageManager(); pm != catalog.PackageManagerApt {
		return nil, errors.New("refused: kernel removal is only supported on apt hosts")
	}
	running, err := e.running()
	if err != nil {
		return nil, err
	}
	all, err := e.installed(ctx)
	if err != nil {
		return nil, err
	}
	kernels := installedKernels(all)
	newest := running
	for _, k := range kernels {
		if debversion.Compare(k, newest) > 0 {
			newest = k
		}
	}

	p := &plan{running: running}
	removing := map[string]bool{}
	for _, r := range releases {
		reason := ""
		switch {
		case !contains(kernels, r):
			reason = "not installed"
		case r == running:
			reason = "it's the running kernel"
		case debversion.Compare(r, running) > 0:
			reason = "newer than the running kernel " + running
		case r == newest:
			reason = "it's the newest installed kernel"
		}
		if reason != "" {
			p.skipped = append(p.skipped, r+": "+reason)
			continue
		}
		removing[r] = true
		p.remove = append(p.remove, r)
	}
	for _, s := range p.skipped {
		e.say("Skipped %s", s)
	}
	if len(p.remove) == 0 {
		return nil, fmt.Errorf("refused: none of the listed kernels can be removed (running %s)", running)
	}

	// A kernel's own packages, plus the headers or tools it shares with
	// other flavours of the same ABI when no kept kernel still uses them.
	keptBases := map[string]bool{base(running): true}
	for _, k := range kernels {
		if !removing[k] {
			keptBases[base(k)] = true
		}
	}
	chosen := map[string]bool{}
	for _, r := range p.remove {
		for _, q := range kernelPackages(all, r) {
			chosen[q.Name] = true
		}
		if !keptBases[base(r)] {
			for _, q := range sharedPackages(all, r) {
				chosen[q.Name] = true
			}
		}
	}
	for _, q := range all {
		if !chosen[q.Name] {
			continue
		}
		switch {
		case strings.HasSuffix(q.Name, "-"+running):
			return nil, fmt.Errorf("refused: %s belongs to the running kernel", q.Name)
		case q.Status[0] == 'h':
			return nil, fmt.Errorf("refused: %s is held", q.Name)
		case q.Status[1] != 'i' && q.Status[1] != 'c':
			return nil, fmt.Errorf("refused: %s is in a broken dpkg state (%s)", q.Name, q.Status)
		}
		p.packages = append(p.packages, q)
	}
	sort.Slice(p.packages, func(i, j int) bool { return p.packages[i].Name < p.packages[j].Name })
	if err := e.simulatePurge(ctx, names(p.packages)); err != nil {
		return nil, err
	}
	return p, nil
}

// validate checks every release against the schema's pattern and drops
// duplicates. One bad entry refuses the whole call.
func validate(releases []string) ([]string, error) {
	var out []string
	for _, r := range releases {
		if len(r) > 64 || !releaseRe.MatchString(r) {
			return nil, fmt.Errorf("bad kernel release %q", r)
		}
		if !contains(out, r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no kernel releases given")
	}
	if len(out) > MaxKernels {
		return nil, fmt.Errorf("%d kernel releases given, at most %d", len(out), MaxKernels)
	}
	return out, nil
}

// running reads the running kernel's release, as uname -r prints it.
func (e *Env) running() (string, error) {
	b, err := os.ReadFile(e.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return "", fmt.Errorf("reading the running kernel's release: %w", err)
	}
	r := strings.TrimSpace(string(b))
	if !releaseRe.MatchString(r) {
		return "", fmt.Errorf("refused: can't read the running kernel's release %q", r)
	}
	return r, nil
}

// installed lists every package dpkg knows, with its status.
func (e *Env) installed(ctx context.Context) ([]pkg, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("dpkg-query exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	var all []pkg
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		status := strings.TrimSpace(f[0])
		if len(status) < 2 {
			return nil, fmt.Errorf("can't read the dpkg status of %s", f[1])
		}
		name, _, _ := strings.Cut(f[1], ":")
		all = append(all, pkg{Status: status[:2], Name: name, Version: f[2]})
	}
	return all, nil
}

// installedKernels lists the releases with an installed kernel image.
func installedKernels(all []pkg) []string {
	var out []string
	for _, q := range all {
		if q.Status[1] != 'i' {
			continue
		}
		for _, prefix := range []string{"linux-image-unsigned-", "linux-image-"} {
			if r, ok := strings.CutPrefix(q.Name, prefix); ok && releaseRe.MatchString(r) {
				if !contains(out, r) {
					out = append(out, r)
				}
				break
			}
		}
	}
	return out
}

// kernelPackages are the packages dpkg knows that belong to exactly this
// release: linux-*-<release>, such as linux-image-, linux-modules-,
// linux-modules-extra- and linux-headers-<release>.
func kernelPackages(all []pkg, release string) []pkg {
	var out []pkg
	for _, q := range all {
		if q.Status[1] != 'n' && strings.HasPrefix(q.Name, "linux-") && strings.HasSuffix(q.Name, "-"+release) {
			out = append(out, q)
		}
	}
	return out
}

// sharedPackages are the headers and tools every flavour of the release's
// ABI shares: linux-headers-6.8.0-45, linux-aws-7.0-headers-7.0.0-1014,
// linux-azure-cloud-tools-7.0.0-1019, Debian's linux-headers-6.1.0-18-common.
func sharedPackages(all []pkg, release string) []pkg {
	b := base(release)
	if b == release {
		return nil
	}
	var out []pkg
	for _, q := range all {
		if q.Status[1] == 'n' || !strings.HasPrefix(q.Name, "linux-") {
			continue
		}
		for _, suffix := range []string{"-headers-" + b, "-tools-" + b, "-headers-" + b + "-common"} {
			if strings.HasSuffix(q.Name, suffix) {
				out = append(out, q)
				break
			}
		}
	}
	return out
}

// base is the release without its flavour: 6.8.0-45 for 6.8.0-45-generic.
func base(release string) string {
	parts := strings.SplitN(release, "-", 3)
	if len(parts) < 3 {
		return release
	}
	return parts[0] + "-" + parts[1]
}

// simulatePurge refuses unless apt would remove exactly these packages and
// install nothing.
func (e *Env) simulatePurge(ctx context.Context, names []string) error {
	out, stderr, code, err := e.run(ctx, aptEnv, append([]string{"/usr/bin/apt-get", "-s", "purge"}, names...)...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("refused: the purge simulation exited with status %d:\n%s", code, tail(stderr))
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var extra, installs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		switch f[0] {
		case "Remv", "Purg":
			seen[name] = true
			if !want[name] {
				extra = append(extra, name)
			}
		case "Inst":
			installs = append(installs, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("refused: purging would also remove packages that must stay: %s", strings.Join(extra, ", "))
	}
	if len(installs) > 0 {
		sort.Strings(installs)
		return fmt.Errorf("refused: purging would also install: %s", strings.Join(installs, ", "))
	}
	for _, n := range names {
		if !seen[n] {
			return fmt.Errorf("refused: the purge simulation doesn't remove %s", n)
		}
	}
	return nil
}

func (e *Env) stream(ctx context.Context, argv []string) error {
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: aptEnv, Stdout: e.Out, Stderr: e.Out})
	if err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	if code != 0 {
		return fmt.Errorf("%s exited with status %d", argv[0], code)
	}
	return nil
}

func names(ps []pkg) []string {
	out := make([]string, len(ps))
	for i, q := range ps {
		out[i] = q.Name
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, "\n")
}
