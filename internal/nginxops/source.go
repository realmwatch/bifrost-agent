package nginxops

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

// nginxOrgKeyring is nginx.org's signing keys as apt reads them, from
// https://nginx.org/keys/nginx_signing.key (dearmored). It holds the key
// nginx.org publishes the fingerprint of (573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62)
// and the newer one that signs its Ubuntu repositories
// (8540A6F18833A80E9C1653A42FD21310B49F6B46). It's compiled in, so the move
// trusts no key fetched at run time.
//
//go:embed nginx-archive-keyring.gpg
var nginxOrgKeyring []byte

const (
	sourceBackupRoot = "/var/backups/nginx-source"
	sourcesDir       = "/etc/apt/sources.list.d"
	keyringPath      = "/usr/share/keyrings/nginx-archive-keyring.gpg"
	nginxListPath    = "/etc/apt/sources.list.d/nginx.list"
	pinPath          = "/etc/apt/preferences.d/99nginx"
	modulesEnabled   = "/etc/nginx/modules-enabled"
	aptGet           = "/usr/bin/apt-get"
	dpkgQuery        = "/usr/bin/dpkg-query"
	pinContent       = "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n"
)

// unshippedModules are the dynamic modules Ondřej Surý's builds load that
// nginx.org's package doesn't ship.
var unshippedModules = regexp.MustCompile(`brotli|geoip|image_filter|image-filter|xslt|ssl_ct|ssl-ct`)

// loadModuleLine is a load_module line on its own, as nginx.conf and the
// modules-enabled files write them.
var loadModuleLine = regexp.MustCompile(`^\s*load_module\s+("?)([^";\s]+)("?)\s*;\s*(#.*)?$`)

var ppaSource = regexp.MustCompile(`ppa\.launchpad(content)?\.net/ondrej/nginx`)

// SourcePlan is what moving to nginx.org's packages would change. The
// nginx_source state tool and the dry run report it.
type SourcePlan struct {
	NginxVersion   string         `json:"nginx_version"`
	PPABuild       bool           `json:"ppa_build"`
	OS             string         `json:"os"`
	Codename       string         `json:"codename"`
	Refusal        string         `json:"refusal"`
	RemoveSources  []string       `json:"remove_sources"`
	Write          []string       `json:"write"`
	SourceLine     string         `json:"source_line"`
	LoadModules    []ModuleLine   `json:"load_module_lines"`
	RemoveLinks    []string       `json:"remove_links"`
	Steps          []string       `json:"steps"`
	Restorable     []string       `json:"restorable"`
	ConfigToChange []configChange `json:"-"`
}

// ModuleLine is a load_module line the move removes.
type ModuleLine struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type configChange struct {
	path  string // a file to edit, or a symlink to remove
	link  bool
	lines []int // 1-based lines to drop
}

// entry is one path the move touches, as it was before.
type entry struct {
	Path   string `json:"path"`
	Group  string `json:"group"` // apt or nginx
	Kind   string `json:"kind"`  // file, symlink or absent
	Backup string `json:"backup,omitempty"`
	Link   string `json:"link,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

type sourceManifest struct {
	Created     string  `json:"created"`
	FromVersion string  `json:"from_version"`
	Entries     []entry `json:"entries"`
}

func (e *Env) installedNginx(ctx context.Context) string {
	var out strings.Builder
	code, err := e.Runner.Run(ctx, runner.Command{Argv: []string{dpkgQuery, "-W", "-f", "${Version}", "nginx"}, Stdout: &out})
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(out.String())
}

// SourcePlanFor works out the move without changing anything.
func (e *Env) SourcePlanFor(ctx context.Context) (*SourcePlan, error) {
	p := &SourcePlan{RemoveSources: []string{}, Write: []string{keyringPath, nginxListPath, pinPath}, LoadModules: []ModuleLine{}, RemoveLinks: []string{}, Restorable: []string{}}
	osr, _ := os.ReadFile(e.path("/etc/os-release"))
	rel := state.ParseOSRelease(string(osr))
	p.OS, p.Codename = rel["PRETTY_NAME"], rel["VERSION_CODENAME"]
	p.NginxVersion = e.installedNginx(ctx)
	p.PPABuild = strings.Contains(p.NginxVersion, "deb.sury.org")
	switch {
	case rel["ID"] != "ubuntu":
		p.Refusal = "this host isn't Ubuntu; the ondrej/nginx PPA was only for Ubuntu"
	case !ubuntuAtLeast(rel["VERSION_ID"], 22, 4):
		p.Refusal = fmt.Sprintf("Ubuntu %s is too old: nginx.org has no fixed builds before 22.04", rel["VERSION_ID"])
	case !regexp.MustCompile(`^[a-z]+$`).MatchString(p.Codename):
		p.Refusal = "os-release names no release codename"
	case p.NginxVersion == "":
		p.Refusal = "the nginx package isn't installed"
	case !p.PPABuild:
		p.Refusal = fmt.Sprintf("nginx %s isn't the ondrej/nginx PPA's build (its version has no deb.sury.org)", p.NginxVersion)
	}
	p.SourceLine = fmt.Sprintf("deb [signed-by=%s] https://nginx.org/packages/mainline/ubuntu %s nginx", keyringPath, p.Codename)

	entries, _ := os.ReadDir(e.path(sourcesDir))
	for _, ent := range entries {
		full := filepath.Join(sourcesDir, ent.Name())
		if strings.HasPrefix(ent.Name(), "ondrej-ubuntu-nginx-") {
			p.RemoveSources = append(p.RemoveSources, full)
			continue
		}
		if b, err := os.ReadFile(e.path(full)); err == nil && ppaSource.Match(b) && full != nginxListPath {
			p.RemoveSources = append(p.RemoveSources, full)
		}
	}

	files := []string{mainConf}
	if mods, err := os.ReadDir(e.path(modulesEnabled)); err == nil {
		for _, m := range mods {
			files = append(files, filepath.Join(modulesEnabled, m.Name()))
		}
	}
	for _, f := range files {
		info, err := os.Lstat(e.path(f))
		if err != nil {
			continue
		}
		b, err := os.ReadFile(e.path(f))
		if err != nil {
			continue
		}
		var drop []int
		other := false
		for i, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "load_module") {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					other = true
				}
				continue
			}
			m := loadModuleLine.FindStringSubmatch(line)
			if m == nil {
				if unshippedModules.MatchString(line) && p.Refusal == "" {
					p.Refusal = fmt.Sprintf("%s:%d loads a module nginx.org doesn't ship in a way this can't edit safely: %s", f, i+1, strings.TrimSpace(line))
				}
				other = true
				continue
			}
			if !unshippedModules.MatchString(filepath.Base(m[2])) {
				other = true
				continue
			}
			drop = append(drop, i+1)
			p.LoadModules = append(p.LoadModules, ModuleLine{File: f, Line: i + 1, Text: strings.TrimSpace(line)})
		}
		if len(drop) == 0 {
			continue
		}
		// A modules-enabled symlink belongs to the module's package: remove
		// the link rather than edit the package's file.
		link := info.Mode()&os.ModeSymlink != 0 && filepath.Dir(f) == modulesEnabled
		if link && other && p.Refusal == "" {
			p.Refusal = fmt.Sprintf("%s links to a file that loads other modules too; remove the module lines by hand", f)
		}
		if link {
			p.RemoveLinks = append(p.RemoveLinks, f)
		}
		p.ConfigToChange = append(p.ConfigToChange, configChange{path: f, link: link, lines: drop})
	}
	backups, err := e.unrestoredSource()
	if err != nil {
		return nil, err
	}
	for _, b := range backups {
		p.Restorable = append(p.Restorable, filepath.Base(b.dir))
	}
	p.Steps = []string{
		"Back up every file below to " + sourceBackupRoot,
		"Remove the load_module lines, then nginx -t with the current nginx",
		"Remove the PPA's sources; install nginx.org's signing key, source and pin (Pin: origin nginx.org, Pin: release o=nginx, priority 900)",
		"apt-get update for nginx.org's source only, then simulate the upgrade",
		"apt-get install --only-upgrade -o Dpkg::Options::=--force-confold nginx",
		"Remove modules-enabled links the upgrade left dangling; nginx -t; restart nginx",
	}
	return p, nil
}

func ubuntuAtLeast(v string, major, minor int) bool {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	ma, err1 := strconv.Atoi(a)
	mi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

// MoveToNginxOrg moves the host from the ondrej/nginx PPA to nginx.org's
// mainline packages. Until the package upgrade, any failure puts every
// file back; the PPA's package can't be put back after it.
func (e *Env) MoveToNginxOrg(ctx context.Context) error {
	p, err := e.SourcePlanFor(ctx)
	if err != nil {
		return err
	}
	if p.Refusal != "" {
		return errors.New("refused: " + p.Refusal)
	}
	if _, err := os.Stat(e.path(nginxBin)); err != nil {
		return fmt.Errorf("refused: no nginx at %s", nginxBin)
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fmt.Errorf("refused, nothing was changed: nginx's configuration already fails its test, so fix that first: %w", err)
	}
	m := sourceManifest{Created: e.Now().UTC().Format(time.RFC3339), FromVersion: p.NginxVersion}
	var paths []struct{ path, group string }
	for _, s := range p.RemoveSources {
		paths = append(paths, struct{ path, group string }{s, "apt"})
	}
	for _, w := range p.Write {
		paths = append(paths, struct{ path, group string }{w, "apt"})
	}
	for _, c := range p.ConfigToChange {
		paths = append(paths, struct{ path, group string }{c.path, "nginx"})
	}
	dir, err := e.newBackupDir(sourceBackupRoot)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	for i, pth := range paths {
		en, err := e.saveEntry(dir, strconv.Itoa(i), pth.path, pth.group)
		if err != nil {
			return fmt.Errorf("backup failed, nothing was changed: %w", err)
		}
		m.Entries = append(m.Entries, en)
	}
	if err := writeManifest(dir, m); err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %d path(s) to %s", len(m.Entries), dir)
	putBack := func(cause error) error {
		if err := e.restoreEntries(m.Entries, dir, nil); err != nil {
			return fmt.Errorf("%w; putting the files back failed too (backup in %s): %v", cause, dir, err)
		}
		_ = os.WriteFile(filepath.Join(dir, restoredMark), []byte(e.Now().UTC().Format(time.RFC3339)+" put back after a failure\n"), 0o600)
		return fmt.Errorf("%w; every file was put back and the PPA's nginx is still installed (backup in %s)", cause, dir)
	}

	// 1. The modules nginx.org doesn't ship, checked with the nginx that
	// still runs, so a config that needs them stops here.
	for _, c := range p.ConfigToChange {
		if err := e.dropLines(c); err != nil {
			return putBack(err)
		}
	}
	for _, l := range p.LoadModules {
		e.say("Removed %s:%d: %s", l.File, l.Line, l.Text)
	}
	if err := e.check(ctx, "nginx -t without the modules nginx.org doesn't ship", nginxBin, "-t"); err != nil {
		return putBack(err)
	}

	// 2. The sources.
	for _, s := range p.RemoveSources {
		if err := os.Remove(e.path(s)); err != nil {
			return putBack(err)
		}
		e.say("Removed %s", s)
	}
	for path, content := range map[string][]byte{keyringPath: nginxOrgKeyring, nginxListPath: []byte(p.SourceLine + "\n"), pinPath: []byte(pinContent)} {
		if err := os.MkdirAll(filepath.Dir(e.path(path)), 0o755); err != nil {
			return putBack(err)
		}
		if err := writeLike(fileEdit{Path: path, Real: e.path(path), Mode: 0o644, UID: -1}, content); err != nil {
			return putBack(err)
		}
		e.say("Wrote %s", path)
	}
	if err := e.apt(ctx, "updating nginx.org's package list", aptGet, "-q", "-o", "Dir::Etc::sourcelist=sources.list.d/nginx.list", "-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0", "update"); err != nil {
		return putBack(err)
	}
	sim, err := e.output(ctx, aptGet, "-s", "-o", "Dpkg::Options::=--force-confold", "install", "--only-upgrade", "nginx")
	if err != nil {
		return putBack(fmt.Errorf("simulating the upgrade: %w", err))
	}
	to, removed := simulated(sim)
	if to == "" || strings.Contains(to, "deb.sury.org") {
		return putBack(fmt.Errorf("apt wouldn't install nginx.org's nginx over %s", p.NginxVersion))
	}
	e.say("apt will install nginx %s from nginx.org", to)
	if len(removed) > 0 {
		e.say("and remove the PPA's %s", strings.Join(removed, ", "))
	}

	// 3. The upgrade. From here the PPA's package can't come back.
	if err := e.apt(ctx, "upgrading nginx", aptGet, "-q", "-y", "-o", "Dpkg::Options::=--force-confold", "install", "--only-upgrade", "nginx"); err != nil {
		return fmt.Errorf("%w; the package state may be half-changed: check with dpkg --audit (backup in %s)", err, dir)
	}
	dangling, err := e.danglingModules(dir, &m)
	if err != nil {
		return err
	}
	for _, d := range dangling {
		e.say("Removed %s, which pointed at a module the upgrade removed", d)
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fmt.Errorf("after the upgrade %w (backup in %s)", err, dir)
	}
	if err := e.check(ctx, "restarting nginx", systemctl, "restart", "nginx"); err != nil {
		return fmt.Errorf("after the upgrade %w (backup in %s)", err, dir)
	}
	if now := e.installedNginx(ctx); now == "" || strings.Contains(now, "deb.sury.org") {
		return fmt.Errorf("after the upgrade dpkg reports nginx %q, not nginx.org's build", now)
	}
	if c, err := load(e.Root); err == nil {
		for _, w := range defaultShadows(c) {
			e.say("WARNING: %s", w)
		}
	}
	e.say("nginx %s from nginx.org is installed and restarted; apt now follows nginx.org's mainline packages", e.installedNginx(ctx))
	return nil
}

// RestoreSource is the rollback of MoveToNginxOrg: it puts back the apt
// sources, key and pin, and the nginx configuration while the PPA's nginx is
// still installed. Once nginx.org's nginx is installed the PPA's package
// can't be reinstalled (Launchpad removed the PPA), so the configuration
// stays as that build needs it.
func (e *Env) RestoreSource(ctx context.Context) error {
	backups, err := e.unrestoredSource()
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		e.say("No move to nginx.org's packages to put back: nothing to do")
		return nil
	}
	b := backups[0]
	version := e.installedNginx(ctx)
	ppa := strings.Contains(version, "deb.sury.org")
	groups := map[string]bool{"apt": true, "nginx": ppa}
	if err := e.restoreEntries(b.m.Entries, b.dir, groups); err != nil {
		return err
	}
	e.say("Put back the apt sources, key and pin from %s", b.dir)
	if ppa {
		e.say("Put back the nginx configuration: the PPA's nginx %s is still installed", version)
		if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
			return err
		}
		if err := e.check(ctx, "reloading nginx", systemctl, "reload", "nginx"); err != nil {
			return err
		}
	} else {
		e.say("nginx %s from nginx.org stays installed: the ondrej/nginx PPA's package can't be reinstalled, because Launchpad removed the PPA, so the nginx configuration stays as this build needs it. The PPA's source is back, but apt can't fetch from it any more.", version)
	}
	return os.WriteFile(filepath.Join(b.dir, restoredMark), []byte(e.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// simulated reads apt-get -s: the nginx version it would install and the
// packages it would remove.
func simulated(out string) (to string, removed []string) {
	inst := regexp.MustCompile(`^Inst nginx (?:\[[^\]]*\] )?\(([^ )]+)`)
	remv := regexp.MustCompile(`^Remv ([^ ]+)`)
	lines := bufio.NewScanner(strings.NewReader(out))
	for lines.Scan() {
		if m := inst.FindStringSubmatch(lines.Text()); m != nil {
			to = m[1]
		}
		if m := remv.FindStringSubmatch(lines.Text()); m != nil {
			removed = append(removed, m[1])
		}
	}
	return to, removed
}

func (e *Env) dropLines(c configChange) error {
	full := e.path(c.path)
	if c.link {
		return os.Remove(full)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var kept []string
	for i, l := range lines {
		drop := false
		for _, n := range c.lines {
			drop = drop || n == i+1
		}
		if !drop {
			kept = append(kept, l)
		}
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return err
	}
	fe, err := statEdit(&file{path: c.path, real: real, content: b})
	if err != nil {
		return err
	}
	return writeLike(fe, []byte(strings.Join(kept, "\n")))
}

// danglingModules removes modules-enabled links whose target the upgrade
// removed, recording each in the backup first.
func (e *Env) danglingModules(dir string, m *sourceManifest) ([]string, error) {
	ents, err := os.ReadDir(e.path(modulesEnabled))
	if err != nil {
		return nil, nil
	}
	var out []string
	for _, ent := range ents {
		p := filepath.Join(modulesEnabled, ent.Name())
		info, err := os.Lstat(e.path(p))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if _, err := os.Stat(e.path(p)); err == nil {
			continue
		}
		en, err := e.saveEntry(dir, strconv.Itoa(len(m.Entries)), p, "nginx")
		if err != nil {
			return nil, err
		}
		m.Entries = append(m.Entries, en)
		if err := writeManifest(dir, *m); err != nil {
			return nil, err
		}
		if err := os.Remove(e.path(p)); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (e *Env) saveEntry(dir, name, path, group string) (entry, error) {
	en := entry{Path: path, Group: group, UID: -1, GID: -1}
	info, err := os.Lstat(e.path(path))
	switch {
	case errors.Is(err, os.ErrNotExist):
		en.Kind = "absent"
		return en, nil
	case err != nil:
		return en, err
	case info.Mode()&os.ModeSymlink != 0:
		en.Kind = "symlink"
		en.Link, err = os.Readlink(e.path(path))
		return en, err
	}
	b, err := os.ReadFile(e.path(path))
	if err != nil {
		return en, err
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		return en, err
	}
	en.Kind, en.Backup, en.Mode = "file", name, uint32(info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		en.UID, en.GID = int(st.Uid), int(st.Gid)
	}
	return en, nil
}

// restoreEntries puts every entry of the groups (all when nil) back as it
// was, in reverse order.
func (e *Env) restoreEntries(entries []entry, dir string, groups map[string]bool) error {
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		en := entries[i]
		if groups != nil && !groups[en.Group] {
			continue
		}
		full := e.path(en.Path)
		switch en.Kind {
		case "absent":
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		case "symlink":
			_ = os.Remove(full)
			if err := os.Symlink(en.Link, full); err != nil {
				errs = append(errs, err)
			}
		case "file":
			b, err := os.ReadFile(filepath.Join(dir, en.Backup))
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				errs = append(errs, err)
				continue
			}
			real := full
			if r, err := filepath.EvalSymlinks(full); err == nil {
				real = r
			}
			if err := writeLike(fileEdit{Path: en.Path, Real: real, Mode: en.Mode, UID: en.UID, GID: en.GID}, b); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", en.Path, err))
			}
		}
	}
	return errors.Join(errs...)
}

type sourceBackup struct {
	dir string
	m   sourceManifest
}

func (e *Env) unrestoredSource() ([]sourceBackup, error) {
	root := e.path(sourceBackupRoot)
	ents, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []sourceBackup
	for _, ent := range ents {
		dir := filepath.Join(root, ent.Name())
		if !ent.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, restoredMark)); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			return nil, fmt.Errorf("reading backup %s: %w", ent.Name(), err)
		}
		var m sourceManifest
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("reading backup %s: %w", ent.Name(), err)
		}
		out = append(out, sourceBackup{dir: dir, m: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir > out[j].dir })
	return out, nil
}

func writeManifest(dir string, m sourceManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600)
}

func (e *Env) newBackupDir(rootPath string) (string, error) {
	root := e.path(rootPath)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", err
	}
	stamp := e.Now().UTC().Format(stampLayout)
	dir := filepath.Join(root, stamp)
	for i := 2; ; i++ {
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) || i > 100 {
			return "", err
		}
		dir = filepath.Join(root, fmt.Sprintf("%s-%d", stamp, i))
	}
}

func (e *Env) apt(ctx context.Context, what string, argv ...string) error {
	var out, errOut strings.Builder
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("%s failed with status %d:\n%s", what, code, lastLines(errOut.String()+out.String(), 20))
	}
	return nil
}

func (e *Env) output(ctx context.Context, argv ...string) (string, error) {
	var out, errOut strings.Builder
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("status %d:\n%s", code, lastLines(errOut.String(), 20))
	}
	return out.String(), nil
}
