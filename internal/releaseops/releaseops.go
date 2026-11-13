// Package releaseops finds and cleans up what an in-place release upgrade
// (do-release-upgrade, 20.04 → 22.04) leaves behind on apt hosts: apt
// sources still naming the old release, packages from the old release that
// no source offers any more, packages built for the old release, and the
// processes that still load them. It runs as root through sudo, and decides
// everything from the host's state when it runs.
package releaseops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/debversion"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

const (
	sourcesDir  = "/etc/apt/sources.list.d"
	backupRoot  = "/var/backups/apt-sources"
	stampLayout = "20060102T150405.000000000Z"

	// MaxPackages is how many packages one removal may name.
	MaxPackages = 100

	// maxListed caps each list in a report.
	maxListed = 200
)

var (
	// FileRe is a file name in /etc/apt/sources.list.d, as the operations take it.
	FileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(list|sources)$`)
	// PackageRe is a Debian package name.
	PackageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)

	aptEnv     = []string{"DEBIAN_FRONTEND=noninteractive"}
	aptOptions = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	libFileRe  = regexp.MustCompile(`\.so(\.[0-9]+)*$`)
)

// releases orders the codenames of each distribution.
var releases = map[string]map[string]float64{
	"ubuntu": {
		"trusty": 14.04, "xenial": 16.04, "bionic": 18.04, "focal": 20.04, "jammy": 22.04,
		"noble": 24.04, "oracular": 24.10, "plucky": 25.04, "questing": 25.10, "resolute": 26.04,
	},
	"debian": {"stretch": 9, "buster": 10, "bullseye": 11, "bookworm": 12, "trixie": 13, "forky": 14},
}

// Env holds what the helpers need; tests replace all of it.
type Env struct {
	Runner runner.Runner
	Root   string
	Out    io.Writer
	Now    func() time.Time
	// Reachable reports whether a URL answers 200, for checking that a
	// source offers the current release before suggesting a retarget.
	Reachable func(ctx context.Context, url string) bool
}

// NewEnv returns an Env for the real system.
func NewEnv(r runner.Runner, out io.Writer) *Env {
	return &Env{Runner: r, Out: out, Now: time.Now, Reachable: reachable}
}

func reachable(ctx context.Context, url string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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

// host is the distribution and release the host runs now.
type host struct {
	distro   string
	codename string
	version  float64
}

func (e *Env) host() (host, error) {
	if pm := (&state.Env{Root: e.Root}).DetectPackageManager(); pm != catalog.PackageManagerApt {
		return host{}, errors.New("refused: release cleanup is only supported on apt hosts")
	}
	b, err := os.ReadFile(e.path("/etc/os-release"))
	if err != nil {
		return host{}, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			fields[k] = strings.Trim(v, `"'`)
		}
	}
	h := host{distro: fields["ID"], codename: fields["VERSION_CODENAME"]}
	v, ok := releases[h.distro][h.codename]
	if !ok {
		return host{}, fmt.Errorf("refused: unknown release %s %q", h.distro, h.codename)
	}
	h.version = v
	return h, nil
}

// older returns the older codename a suite names (focal for focal-pgdg),
// or "" when it names the current release, a newer one or none.
func (h host) older(suite string) string {
	name, _, _ := strings.Cut(suite, "-")
	v, ok := releases[h.distro][name]
	if !ok || v >= h.version {
		return ""
	}
	return name
}

// retargeted is the suite for the current release: focal-pgdg → jammy-pgdg.
func (h host) retargeted(suite string) string {
	name := h.older(suite)
	if name == "" {
		return suite
	}
	return h.codename + strings.TrimPrefix(suite, name)
}

// ---- Sources ---------------------------------------------------------------

// Source is one apt source entry that names an older release.
type Source struct {
	File      string `json:"file"`
	URI       string `json:"uri"`
	Suite     string `json:"suite"`
	NewSuite  string `json:"new_suite"`
	Available bool   `json:"available"`
	// Action is what the cleanup proposes: retarget when the source offers
	// the current release at the same URI, else disable.
	Action string `json:"action"`
}

// DisabledSource is a source line the release upgrade commented out.
type DisabledSource struct {
	File string `json:"file"`
	Line string `json:"line"`
}

var disabledOnUpgradeRe = regexp.MustCompile(`^#\s*(deb(?:-src)?\s.*?)\s*#\s*disabled on upgrade to ([a-z]+)\s*$`)

func (e *Env) disabledSources() ([]DisabledSource, error) {
	files, err := e.sourceFiles()
	if err != nil {
		return nil, err
	}
	out := []DisabledSource{}
	for _, f := range files {
		b, err := os.ReadFile(e.path(filepath.Join(sourcesDir, f)))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if m := disabledOnUpgradeRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				out = append(out, DisabledSource{File: f, Line: m[1]})
			}
		}
	}
	return out, nil
}

// entry is one source line or deb822 stanza's suite, with its URI.
type entry struct{ uri, suite string }

func (e *Env) sourceFiles() ([]string, error) {
	des, err := os.ReadDir(e.path(sourcesDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, de := range des {
		if de.Type().IsRegular() && FileRe.MatchString(de.Name()) {
			out = append(out, de.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// entries parses a sources file into its (URI, suite) pairs. Disabled
// deb822 stanzas and comments don't count.
func entries(name, content string) []entry {
	var out []entry
	if strings.HasSuffix(name, ".list") {
		for _, line := range strings.Split(content, "\n") {
			if uri, suite, ok := parseListLine(line); ok {
				out = append(out, entry{uri, suite})
			}
		}
		return out
	}
	for _, stanza := range stanzas(content) {
		if strings.EqualFold(stanza.field("Enabled"), "no") {
			continue
		}
		for _, uri := range strings.Fields(stanza.field("URIs")) {
			for _, suite := range strings.Fields(stanza.field("Suites")) {
				out = append(out, entry{uri, suite})
			}
		}
	}
	return out
}

// parseListLine reads "deb [opts] uri suite components…".
func parseListLine(line string) (uri, suite string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	f := strings.Fields(line)
	if len(f) < 3 || (f[0] != "deb" && f[0] != "deb-src") {
		return "", "", false
	}
	i := 1
	if strings.HasPrefix(f[i], "[") {
		for i < len(f) && !strings.HasSuffix(f[i], "]") {
			i++
		}
		i++
	}
	if i+1 >= len(f) {
		return "", "", false
	}
	return f[i], f[i+1], true
}

type stanza struct{ lines []string }

func stanzas(content string) []stanza {
	var out []stanza
	cur := stanza{}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur.lines) > 0 {
				out = append(out, cur)
			}
			cur = stanza{}
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	if len(cur.lines) > 0 {
		out = append(out, cur)
	}
	return out
}

func (s stanza) field(name string) string {
	for _, line := range s.lines {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// staleSources lists the entries naming an older release, one per file,
// URI and suite.
func (e *Env) staleSources(ctx context.Context, h host) ([]Source, error) {
	files, err := e.sourceFiles()
	if err != nil {
		return nil, err
	}
	var out []Source
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(e.path(filepath.Join(sourcesDir, f)))
		if err != nil {
			return nil, err
		}
		for _, en := range entries(f, string(b)) {
			key := f + "\x00" + en.uri + "\x00" + en.suite
			if seen[key] || h.older(en.suite) == "" {
				continue
			}
			seen[key] = true
			s := Source{File: f, URI: en.uri, Suite: en.suite, NewSuite: h.retargeted(en.suite)}
			if strings.HasPrefix(en.uri, "http://") || strings.HasPrefix(en.uri, "https://") {
				base := strings.TrimSuffix(en.uri, "/") + "/dists/" + s.NewSuite + "/"
				s.Available = e.Reachable(ctx, base+"InRelease") || e.Reachable(ctx, base+"Release")
			}
			out = append(out, s)
		}
	}
	// A source behind authentication (Ubuntu ESM) won't answer a plain
	// request; it offers the current release if the same URI is already
	// configured with the current release's suite.
	current := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(e.path(filepath.Join(sourcesDir, f)))
		if err != nil {
			return nil, err
		}
		for _, en := range entries(f, string(b)) {
			current[strings.TrimSuffix(en.uri, "/")+"\x00"+en.suite] = true
		}
	}
	for i := range out {
		if current[strings.TrimSuffix(out[i].URI, "/")+"\x00"+out[i].NewSuite] {
			out[i].Available = true
		}
	}
	// A file is retargeted only if every stale source in it offers the
	// current release; otherwise the whole file is disabled.
	byFile := map[string]bool{}
	for _, s := range out {
		if _, ok := byFile[s.File]; !ok {
			byFile[s.File] = true
		}
		byFile[s.File] = byFile[s.File] && s.Available
	}
	for i := range out {
		out[i].Action = "disable"
		if byFile[out[i].File] {
			out[i].Action = "retarget"
		}
	}
	return out, nil
}

// ---- Packages --------------------------------------------------------------

// Package is one installed package the upgrade left behind.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// BuiltFor is the older release the package was built for ("focal"),
	// "older" when only its origin says so, or "" for a local package.
	BuiltFor string `json:"built_for,omitempty"`
	// Replacement is a version a source offers for the current release, with
	// the same epoch and an upstream version at least as new; empty when
	// none does.
	Replacement string `json:"replacement,omitempty"`
}

// Use is a running process that loads a leftover package's library.
type Use struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
	Unit    string `json:"unit,omitempty"`
	Library string `json:"library"`
	Package string `json:"package"`
}

// Report is what `release leftovers` prints.
type Report struct {
	Codename string   `json:"codename"`
	Sources  []Source `json:"sources"`
	// Disabled are sources the release upgrade commented out ("disabled on
	// upgrade to jammy"): packages from them may have no source now. Only
	// reported: nothing re-enables a source.
	Disabled []DisabledSource `json:"disabled"`
	Obsolete []Package        `json:"obsolete"`
	// Local are obsolete packages that weren't built for an older release,
	// such as a vendor's .deb: listed, never proposed for removal.
	Local     []Package `json:"local"`
	OldBuilds []Package `json:"old_builds"`
	UsedBy    []Use     `json:"used_by"`
	Truncated bool      `json:"truncated"`
}

var (
	// Ubuntu release markers: 0.20.04 (an update for 20.04), +ubuntu20.04
	// (third-party builds), ~20.04 (backports and PPAs), pgdg20.04
	// (PostgreSQL's builds). "ubuntu14.22" alone is a package revision.
	ubuntuMarkRe = regexp.MustCompile(`(?:ubuntu0\.|\+ubuntu|~|pgdg)([0-9]{2})\.([0-9]{2})(?:[^0-9]|$)`)
	codenameRe   = regexp.MustCompile(`[~+.]([a-z]+)[0-9]*`)
	debianMarkRe = regexp.MustCompile(`(?:\+deb|~deb)([0-9]{1,2})u`)
)

// builtFor reads the older release a version string names: ubuntu0.20.04.3,
// +ubuntu20.04.1, ~20.04.1, pgdg20.04, ~focal1, +deb11u1. Empty when it
// names none, the current release, or no release Bifrost knows.
func (h host) builtFor(version string) string {
	named := func(distro string, v float64) string {
		if v <= 0 || v >= h.version {
			return ""
		}
		for name, rv := range releases[distro] {
			if rv == v {
				return name
			}
		}
		return ""
	}
	if h.distro == "ubuntu" {
		for _, m := range ubuntuMarkRe.FindAllStringSubmatch(version, -1) {
			v, _ := strconv.ParseFloat(m[1]+"."+m[2], 64)
			if name := named("ubuntu", v); name != "" {
				return name
			}
		}
	}
	if h.distro == "debian" {
		for _, m := range debianMarkRe.FindAllStringSubmatch(version, -1) {
			v, _ := strconv.ParseFloat(m[1], 64)
			if name := named("debian", v); name != "" {
				return name
			}
		}
	}
	for _, m := range codenameRe.FindAllStringSubmatch(version, -1) {
		if name := h.older(m[1]); name != "" {
			return name
		}
	}
	return ""
}

// upstream splits a version into its epoch and upstream parts: 6:8.0.6-1
// → ("6", "8.0.6").
func upstream(version string) (epoch, up string) {
	epoch, rest, ok := strings.Cut(version, ":")
	if !ok {
		epoch, rest = "0", version
	}
	if i := strings.LastIndex(rest, "-"); i > 0 {
		rest = rest[:i]
	}
	return epoch, rest
}

// acceptable says whether a replacement may stand in for an installed
// version: the same epoch, and an upstream version at least as new, so a
// cleanup never moves a service to an older major release (Redis 8 to 6).
func acceptable(installed, replacement string) bool {
	ie, iu := upstream(installed)
	re, ru := upstream(replacement)
	return ie == re && debversion.Compare(ru, iu) >= 0
}

type installed struct{ name, version, maintainer string }

func (e *Env) installed(ctx context.Context) (map[string]installed, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Maintainer}\n")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("dpkg-query exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	pkgs := map[string]installed{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || len(f[0]) < 2 || f[0][1] != 'i' {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		pkgs[name] = installed{name: name, version: f[2], maintainer: f[3]}
	}
	return pkgs, nil
}

// obsoleteNames lists installed packages no configured source offers at
// their installed version (apt list marks them "local").
func (e *Env) obsoleteNames(ctx context.Context) (map[string]bool, error) {
	out, stderr, code, err := e.run(ctx, aptEnv, "/usr/bin/apt", "list", "--installed")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("apt list exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	names := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "[installed,local]") {
			continue
		}
		name, _, _ := strings.Cut(line, "/")
		names[name] = true
	}
	return names, nil
}

// fromDistro says whether a maintainer is the distribution's own, so an
// obsolete package with no release in its version still came from it.
func fromDistro(maintainer string) bool {
	m := strings.ToLower(maintainer)
	return strings.Contains(m, "ubuntu developers") || strings.Contains(m, "debian")
}

// replacement is the highest version a configured source offers that isn't
// built for an older release, from apt-cache policy's version table.
func (e *Env) replacements(ctx context.Context, h host, names []string) (map[string]string, error) {
	out := map[string]string{}
	if len(names) == 0 {
		return out, nil
	}
	stdout, stderr, code, err := e.run(ctx, aptEnv, append([]string{"/usr/bin/apt-cache", "policy"}, names...)...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("apt-cache policy exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	pkg, version, offered := "", "", false
	flush := func() {
		if pkg != "" && version != "" && offered && h.builtFor(version) == "" {
			if cur, ok := out[pkg]; !ok || debversion.Compare(version, cur) > 0 {
				out[pkg] = version
			}
		}
		version, offered = "", false
	}
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case line != "" && !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			flush()
			pkg = strings.TrimSuffix(line, ":")
		case strings.HasPrefix(line, "     ") && !strings.HasPrefix(line, "        "):
			// A version line: "     1.2-3 500" or " *** 1.2-3 100".
			flush()
			f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "***"))
			if len(f) >= 1 {
				version = f[0]
			}
		case strings.HasPrefix(line, " *** "):
			flush()
			f := strings.Fields(strings.TrimPrefix(line, " *** "))
			if len(f) >= 1 {
				version = f[0]
			}
		case strings.HasPrefix(line, "        "):
			// A source line under a version; /var/lib/dpkg/status isn't one.
			if !strings.Contains(line, "/var/lib/dpkg/status") {
				offered = true
			}
		}
	}
	flush()
	return out, nil
}

// libraries lists the shared libraries a package ships.
func (e *Env) libraries(ctx context.Context, pkg string) ([]string, error) {
	out, _, code, err := e.run(ctx, nil, "/usr/bin/dpkg", "-L", pkg)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, nil
	}
	var libs []string
	for _, p := range strings.Split(out, "\n") {
		p = strings.TrimSpace(p)
		if libFileRe.MatchString(p) {
			libs = append(libs, p)
		}
	}
	return libs, nil
}

// users finds the running processes that map any of the libraries.
func (e *Env) users(libs map[string]string) ([]Use, error) {
	if len(libs) == 0 {
		return nil, nil
	}
	// Match by file name: /lib and /usr/lib are often the same directory.
	byBase := map[string]string{}
	for lib, pkg := range libs {
		byBase[filepath.Base(lib)] = pkg
	}
	des, err := os.ReadDir(e.path("/proc"))
	if err != nil {
		return nil, err
	}
	var out []Use
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		maps, err := os.ReadFile(e.path(fmt.Sprintf("/proc/%d/maps", pid)))
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(string(maps), "\n") {
			f := strings.Fields(line)
			if len(f) < 6 {
				continue
			}
			file := f[len(f)-1]
			pkg, ok := byBase[filepath.Base(file)]
			if !ok || seen[file] {
				continue
			}
			seen[file] = true
			comm, _ := os.ReadFile(e.path(fmt.Sprintf("/proc/%d/comm", pid)))
			out = append(out, Use{PID: pid, Command: strings.TrimSpace(string(comm)), Unit: e.unitOf(pid), Library: file, Package: pkg})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].Library < out[j].Library
	})
	return out, nil
}

var unitRe = regexp.MustCompile(`([A-Za-z0-9:_.@-]+\.service)$`)

// unitOf reads the systemd service a process runs in, from its cgroup.
func (e *Env) unitOf(pid int) string {
	b, err := os.ReadFile(e.path(fmt.Sprintf("/proc/%d/cgroup", pid)))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m := unitRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1]
		}
	}
	return ""
}

// Leftovers reports what the upgrade left behind.
func (e *Env) Leftovers(ctx context.Context) (*Report, error) {
	h, err := e.host()
	if err != nil {
		return nil, err
	}
	r := &Report{Codename: h.codename, Sources: []Source{}, Obsolete: []Package{}, Local: []Package{}, OldBuilds: []Package{}, UsedBy: []Use{}}
	if r.Sources, err = e.staleSources(ctx, h); err != nil {
		return nil, err
	}
	if r.Sources == nil {
		r.Sources = []Source{}
	}
	if r.Disabled, err = e.disabledSources(); err != nil {
		return nil, err
	}
	pkgs, err := e.installed(ctx)
	if err != nil {
		return nil, err
	}
	obsolete, err := e.obsoleteNames(ctx)
	if err != nil {
		return nil, err
	}
	var oldNames []string
	names := make([]string, 0, len(pkgs))
	for name := range pkgs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := pkgs[name]
		built := h.builtFor(p.version)
		switch {
		case obsolete[name] && built == "" && fromDistro(p.maintainer):
			r.Obsolete = append(r.Obsolete, Package{Name: name, Version: p.version, BuiltFor: "older"})
		case obsolete[name] && built != "":
			r.Obsolete = append(r.Obsolete, Package{Name: name, Version: p.version, BuiltFor: built})
		case obsolete[name]:
			r.Local = append(r.Local, Package{Name: name, Version: p.version})
		case built != "":
			r.OldBuilds = append(r.OldBuilds, Package{Name: name, Version: p.version, BuiltFor: built})
			oldNames = append(oldNames, name)
		}
	}
	for _, p := range r.Obsolete {
		oldNames = append(oldNames, p.Name)
	}
	repl, err := e.replacements(ctx, h, oldNames)
	if err != nil {
		return nil, err
	}
	for _, list := range []*[]Package{&r.Obsolete, &r.OldBuilds} {
		for i := range *list {
			p := &(*list)[i]
			if v, ok := repl[p.Name]; ok && v != p.Version && acceptable(p.Version, v) {
				p.Replacement = v
			}
		}
	}
	libs := map[string]string{}
	for _, p := range append(append([]Package{}, r.Obsolete...), r.OldBuilds...) {
		files, err := e.libraries(ctx, p.Name)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			libs[f] = p.Name
		}
	}
	if r.UsedBy, err = e.users(libs); err != nil {
		return nil, err
	}
	if r.UsedBy == nil {
		r.UsedBy = []Use{}
	}
	for _, list := range []*[]Package{&r.Obsolete, &r.Local, &r.OldBuilds} {
		if len(*list) > maxListed {
			*list = (*list)[:maxListed]
			r.Truncated = true
		}
	}
	if len(r.UsedBy) > maxListed {
		r.UsedBy = r.UsedBy[:maxListed]
		r.Truncated = true
	}
	return r, nil
}

// ---- Source edits ----------------------------------------------------------

func (e *Env) sourcePath(file string) (string, error) {
	if !FileRe.MatchString(file) || len(file) > 128 {
		return "", fmt.Errorf("bad sources file name %q", file)
	}
	return e.path(filepath.Join(sourcesDir, file)), nil
}

// backup copies a sources file to a new directory under the backup root
// and returns it.
func (e *Env) backup(file, path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	root := e.path(backupRoot)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	dir := filepath.Join(root, e.Now().UTC().Format(stampLayout))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, file), b, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// Retarget changes every suite in the file that names an older release to
// the current one (focal → jammy, focal-pgdg → jammy-pgdg), never its URIs
// or keys. It refreshes those entries to prove the source offers the
// release and signs it with the key it already trusts, and keeps the old
// file if not.
func (e *Env) Retarget(ctx context.Context, file string) error {
	path, err := e.sourcePath(file)
	if err != nil {
		return err
	}
	h, err := e.host()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated, changed := retargetContent(h, file, string(b))
	if len(changed) == 0 {
		return fmt.Errorf("refused: %s names no older release", file)
	}
	dir, err := e.backup(file, path)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %s to %s", file, dir)

	// Refresh only the changed file, from a copy, before writing it.
	trial := filepath.Join(dir, "trial-"+file)
	if err := os.WriteFile(trial, []byte(updated), 0o644); err != nil {
		return err
	}
	trialDir := filepath.Join(dir, "trial.d")
	if err := os.MkdirAll(trialDir, 0o755); err != nil {
		return err
	}
	if err := os.Rename(trial, filepath.Join(trialDir, file)); err != nil {
		return err
	}
	_, stderr, code, err := e.run(ctx, aptEnv, "/usr/bin/apt-get", "-q", "update",
		"-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Dir::Etc::sourceparts="+trialDir, "-o", "APT::Get::List-Cleanup=0")
	if err != nil {
		return err
	}
	if code != 0 || strings.Contains(stderr, "NO_PUBKEY") || strings.Contains(stderr, "is not signed") || strings.Contains(stderr, "does not have a Release file") {
		return fmt.Errorf("refused: the source doesn't offer %s signed by its current key, so %s was left as it was:\n%s", h.codename, file, tail(stderr))
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	e.say("Retargeted %s: %s", file, strings.Join(changed, ", "))
	return nil
}

// retargetContent rewrites the suites naming an older release. A line that
// would duplicate one already in the file is dropped instead.
func retargetContent(h host, file, content string) (string, []string) {
	var changed []string
	note := func(from, to string) {
		c := from + " → " + to
		for _, x := range changed {
			if x == c {
				return
			}
		}
		changed = append(changed, c)
	}
	if strings.HasSuffix(file, ".list") {
		lines := strings.Split(content, "\n")
		present := map[string]bool{}
		for _, l := range lines {
			present[strings.Join(strings.Fields(l), " ")] = true
		}
		var out []string
		for _, l := range lines {
			uri, suite, ok := parseListLine(l)
			if !ok || h.older(suite) == "" {
				out = append(out, l)
				continue
			}
			f := strings.Fields(l)
			for i := range f {
				if f[i] == suite && i > 0 && f[i-1] == uri {
					f[i] = h.retargeted(suite)
				}
			}
			note(suite, h.retargeted(suite))
			nl := strings.Join(f, " ")
			if present[nl] {
				continue
			}
			present[nl] = true
			out = append(out, nl)
		}
		return strings.Join(out, "\n"), changed
	}
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Suites") {
			continue
		}
		var suites []string
		seen := map[string]bool{}
		for _, s := range strings.Fields(v) {
			n := h.retargeted(s)
			if n != s {
				note(s, n)
			}
			if !seen[n] {
				seen[n] = true
				suites = append(suites, n)
			}
		}
		lines[i] = strings.TrimSpace(k) + ": " + strings.Join(suites, " ")
	}
	return strings.Join(lines, "\n"), changed
}

// Disable backs up a sources file and removes it, so apt no longer uses it.
func (e *Env) Disable(_ context.Context, file string) error {
	path, err := e.sourcePath(file)
	if err != nil {
		return err
	}
	if _, err := e.host(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("refused: no sources file %s", file)
	}
	dir, err := e.backup(file, path)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	e.say("Disabled %s; backup in %s", file, dir)
	return nil
}

// Restore puts back the newest backup of a sources file: the rollback of
// Retarget and Disable.
func (e *Env) Restore(_ context.Context, file string) error {
	path, err := e.sourcePath(file)
	if err != nil {
		return err
	}
	des, err := os.ReadDir(e.path(backupRoot))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	newest := ""
	for _, de := range des {
		if de.IsDir() && de.Name() > newest {
			if _, err := os.Stat(filepath.Join(e.path(backupRoot), de.Name(), file)); err == nil {
				newest = de.Name()
			}
		}
	}
	if newest == "" {
		if _, err := os.Stat(path); err == nil {
			e.say("%s has no backup and is in place: nothing to restore", file)
			return nil
		}
		return fmt.Errorf("no backup of %s to restore", file)
	}
	b, err := os.ReadFile(filepath.Join(e.path(backupRoot), newest, file))
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	e.say("Restored %s from %s", file, filepath.Join(backupRoot, newest))
	return nil
}

// ---- Obsolete packages -----------------------------------------------------

// RemoveObsolete purges the listed packages that are obsolete and from an
// older release. It refuses, changing nothing, while a running process
// loads one of their libraries or if the purge would remove or install
// anything else. A listed package that isn't such a leftover is skipped.
func (e *Env) RemoveObsolete(ctx context.Context, names []string) error {
	names, err := validNames(names)
	if err != nil {
		return err
	}
	r, err := e.Leftovers(ctx)
	if err != nil {
		return err
	}
	leftover := map[string]Package{}
	for _, p := range r.Obsolete {
		leftover[p.Name] = p
	}
	var remove []string
	for _, n := range names {
		if _, ok := leftover[n]; !ok {
			e.say("Skipped %s: not an obsolete package from an older release", n)
			continue
		}
		remove = append(remove, n)
	}
	if len(remove) == 0 {
		return errors.New("refused: none of the listed packages is an obsolete package from an older release")
	}
	removing := map[string]bool{}
	for _, n := range remove {
		removing[n] = true
	}
	var used []string
	for _, u := range r.UsedBy {
		if removing[u.Package] {
			used = append(used, fmt.Sprintf("%s (pid %d%s) loads %s from %s", u.Command, u.PID, unitNote(u.Unit), u.Library, u.Package))
		}
	}
	if len(used) > 0 {
		return fmt.Errorf("refused: still in use; restart these first:\n%s", strings.Join(used, "\n"))
	}
	if err := e.simulatePurge(ctx, remove); err != nil {
		return err
	}
	argv := append([]string{"/usr/bin/apt-get", "-q", "-y"}, aptOptions...)
	argv = append(append(argv, "purge"), remove...)
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: aptEnv, Stdout: e.Out, Stderr: e.Out})
	if err != nil {
		return fmt.Errorf("purge failed: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("purge failed: apt-get exited with status %d", code)
	}
	now, err := e.installed(ctx)
	if err != nil {
		return fmt.Errorf("can't confirm the purge: %w", err)
	}
	var left []string
	for _, n := range remove {
		if _, ok := now[n]; ok {
			left = append(left, n)
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("still installed after the purge: %s", strings.Join(left, ", "))
	}
	e.say("Removed obsolete packages:")
	for _, n := range remove {
		e.say("  %s %s (built for %s)", n, leftover[n].Version, leftover[n].BuiltFor)
	}
	return nil
}

func unitNote(unit string) string {
	if unit == "" {
		return ""
	}
	return ", " + unit
}

func validNames(names []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if len(n) > 128 || !PackageRe.MatchString(n) {
			return nil, fmt.Errorf("bad package name %q", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no packages given")
	}
	if len(out) > MaxPackages {
		return nil, fmt.Errorf("%d packages given, at most %d", len(out), MaxPackages)
	}
	return out, nil
}

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
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		switch f[0] {
		case "Remv", "Purg":
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
	return nil
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, "\n")
}
