// Package phpops removes and restores one PHP version on apt hosts. It runs
// as root through sudo, with every check made at execution time, because a
// report from earlier can't prove the version is still unused.
package phpops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/runner"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

const (
	backupRoot   = "/var/backups/php-remove"
	manifestName = "packages.tsv"
	configTar    = "etc-php.tar"
	stampLayout  = "20060102T150405Z"
)

var (
	versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	backupRe  = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	pkgVerRe  = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:_-]*$`)

	aptEnv     = []string{"DEBIAN_FRONTEND=noninteractive"}
	aptOptions = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
)

// Env holds what the operations need; tests replace all of it.
type Env struct {
	Runner runner.Runner
	Root   string
	Now    func() time.Time
	Out    io.Writer
}

// pkg is one installed package.
type pkg struct{ Name, Version string }

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

func (e *Env) checkHost(version string) error {
	if !versionRe.MatchString(version) || len(version) > 16 {
		return fmt.Errorf("bad PHP version %q", version)
	}
	if pm := (&state.Env{Root: e.Root}).DetectPackageManager(); pm != catalog.PackageManagerApt {
		return errors.New("refused: PHP removal is only supported on apt hosts")
	}
	return nil
}

// Remove checks that nothing uses the version, backs it up, then purges it.
func (e *Env) Remove(ctx context.Context, version string) error {
	if err := e.checkHost(version); err != nil {
		return err
	}
	for _, check := range []func(context.Context, string) error{e.checkFPM, e.checkSiteConfigs, e.checkAlternative, e.checkReferences} {
		if err := check(ctx, version); err != nil {
			return err
		}
	}
	installed, err := e.packages(ctx, version)
	if err != nil {
		return err
	}
	if len(installed) == 0 {
		return fmt.Errorf("refused: no php%s packages are installed", version)
	}
	names := make([]string, len(installed))
	for i, p := range installed {
		names[i] = p.Name
	}
	if err := e.simulatePurge(ctx, names); err != nil {
		return err
	}
	e.say("Every check passed for PHP %s: %s", version, strings.Join(names, " "))

	dir, err := e.backup(ctx, version, installed)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was removed: %w", err)
	}
	e.say("Backed up to %s", dir)

	argv := append([]string{"/usr/bin/apt-get", "-q", "-y"}, aptOptions...)
	argv = append(append(argv, "purge"), names...)
	if err := e.stream(ctx, argv); err != nil {
		return fmt.Errorf("purge failed (backup kept at %s): %w", dir, err)
	}

	left, err := e.packages(ctx, version)
	if err != nil {
		return fmt.Errorf("can't confirm the purge (backup kept at %s): %w", dir, err)
	}
	if len(left) > 0 {
		return fmt.Errorf("packages are still installed after the purge (backup kept at %s): %s", dir, joinPkgs(left))
	}
	e.say("PHP %s is removed. Backup: %s", version, dir)
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

func (e *Env) checkFPM(ctx context.Context, version string) error {
	unit := "php" + version + "-fpm"
	out, _, code, err := e.run(ctx, nil, "/usr/bin/systemctl", "is-active", unit)
	if err != nil {
		return err
	}
	switch active := strings.TrimSpace(out); {
	case code == 0:
		return fmt.Errorf("refused: %s is active", unit)
	case active != "inactive" && active != "failed" && active != "unknown":
		return fmt.Errorf("refused: %s is %s", unit, orUnknown(active))
	}
	out, _, code, err = e.run(ctx, nil, "/usr/bin/systemctl", "is-enabled", unit)
	if err != nil {
		return err
	}
	if code == 0 {
		return fmt.Errorf("refused: %s is %s", unit, orUnknown(strings.TrimSpace(out)))
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "in an unknown state"
	}
	return s
}

// checkSiteConfigs looks for the version's socket or handler in web server
// config. Comment lines don't count: distro default sites carry commented-out
// examples. Apache's *-available directories hold what packages ship; what's
// in use is linked from *-enabled, which is read through the link.
func (e *Env) checkSiteConfigs(_ context.Context, version string) error {
	quoted := regexp.QuoteMeta(version)
	re := regexp.MustCompile(`php/?` + quoted + `([^0-9]|$)`)
	var hits []string
	for _, root := range []string{"/etc/nginx", "/etc/apache2"} {
		err := filepath.WalkDir(e.path(root), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				if d.Name() == "conf-available" || d.Name() == "mods-available" {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := os.Stat(p)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil // a dangling link configures nothing
				}
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && re.MatchString(line) {
					hits = append(hits, fmt.Sprintf("%s:%d", strings.TrimPrefix(p, e.Root), i+1))
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("reading web server config: %w", err)
		}
	}
	if len(hits) > 0 {
		return fmt.Errorf("refused: web server config references PHP %s:\n%s", version, strings.Join(hits, "\n"))
	}
	return nil
}

func (e *Env) checkAlternative(_ context.Context, version string) error {
	target, err := os.Readlink(e.path("/etc/alternatives/php"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the php alternative: %w", err)
	}
	if filepath.Base(target) == "php"+version {
		return fmt.Errorf("refused: the php alternative points at %s; point it elsewhere first", target)
	}
	return nil
}

func (e *Env) checkReferences(ctx context.Context, version string) error {
	cron, err := filepath.Glob(e.path("/etc/cron*"))
	if err != nil {
		return err
	}
	var paths []string
	for _, p := range append(cron, e.path("/var/spool/cron"), e.path("/etc/supervisor"), e.path("/etc/systemd/system")) {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	pattern := "php" + regexp.QuoteMeta(version) + "([^0-9]|$)"
	out, stderr, code, err := e.run(ctx, nil, append([]string{"/usr/bin/grep", "-rlsE", pattern}, paths...)...)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return fmt.Errorf("refused: these files reference php%s:\n%s", version, strings.TrimSpace(out))
	case 1:
		return nil
	default:
		return fmt.Errorf("searching for references failed with status %d: %s", code, strings.TrimSpace(stderr))
	}
}

// packages lists the installed phpX.Y and phpX.Y-* packages, sorted. A
// package in a broken dpkg state is an error: nothing can be said about it.
func (e *Env) packages(ctx context.Context, version string) ([]pkg, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("dpkg-query exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	base := "php" + version
	var found []pkg
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || (f[1] != base && !strings.HasPrefix(f[1], base+"-")) {
			continue
		}
		status := f[0]
		if len(status) < 2 {
			return nil, fmt.Errorf("can't read the dpkg status of %s", f[1])
		}
		switch status[1] {
		case 'n', 'c':
			continue
		case 'i':
		default:
			return nil, fmt.Errorf("refused: %s is in a broken dpkg state (%s)", f[1], strings.TrimSpace(status))
		}
		if status[0] == 'h' {
			return nil, fmt.Errorf("refused: %s is held", f[1])
		}
		found = append(found, pkg{Name: f[1], Version: f[2]})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, nil
}

// simulatedChanges parses apt-get -s output into removed and installed names.
func simulatedChanges(out string) (removed, installed []string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, _, _ := strings.Cut(f[1], ":")
		switch f[0] {
		case "Remv", "Purg":
			removed = append(removed, name)
		case "Inst":
			installed = append(installed, name)
		}
	}
	return removed, installed
}

func (e *Env) simulatePurge(ctx context.Context, names []string) error {
	out, stderr, code, err := e.run(ctx, aptEnv, append([]string{"/usr/bin/apt-get", "-s", "purge"}, names...)...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("refused: the purge simulation exited with status %d:\n%s", code, tail(stderr))
	}
	removed, installed := simulatedChanges(out)
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var extra []string
	seen := map[string]bool{}
	for _, n := range removed {
		seen[n] = true
		if !want[n] {
			extra = append(extra, n)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("refused: purging would also remove packages that must stay: %s", strings.Join(extra, ", "))
	}
	if len(installed) > 0 {
		sort.Strings(installed)
		return fmt.Errorf("refused: purging would also install: %s", strings.Join(installed, ", "))
	}
	for _, n := range names {
		if !seen[n] {
			return fmt.Errorf("refused: the purge simulation doesn't remove %s", n)
		}
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

func joinPkgs(ps []pkg) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

func (e *Env) backup(ctx context.Context, version string, installed []pkg) (string, error) {
	root, versionDir := e.path(backupRoot), e.path(filepath.Join(backupRoot, version))
	for _, d := range []string{root, versionDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return "", err
		}
	}
	dir := filepath.Join(versionDir, e.Now().UTC().Format(stampLayout))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	var manifest strings.Builder
	for _, p := range installed {
		fmt.Fprintf(&manifest, "%s\t%s\n", p.Name, p.Version)
	}
	f, err := os.OpenFile(filepath.Join(dir, manifestName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(manifest.String()); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if _, err := os.Stat(e.path("/etc/php/" + version)); err == nil {
		_, stderr, code, err := e.run(ctx, nil, "/usr/bin/tar", "-C", e.path("/etc/php"), "-cpf", filepath.Join(dir, configTar), version)
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("tar exited with status %d: %s", code, strings.TrimSpace(stderr))
		}
		if err := os.Chmod(filepath.Join(dir, configTar), 0o600); err != nil {
			return "", err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return dir, nil
}

// findBackup returns the named backup, or the newest when backup is empty.
// It returns "" when backup is empty and there are none.
func (e *Env) findBackup(version, backup string) (string, error) {
	versionDir := e.path(filepath.Join(backupRoot, version))
	if backup != "" {
		if !backupRe.MatchString(backup) {
			return "", fmt.Errorf("bad backup name %q", backup)
		}
		dir := filepath.Join(versionDir, backup)
		if _, err := os.Stat(filepath.Join(dir, manifestName)); err != nil {
			return "", fmt.Errorf("no backup %s for PHP %s", backup, version)
		}
		return dir, nil
	}
	entries, err := os.ReadDir(versionDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	newest := ""
	for _, entry := range entries {
		if backupRe.MatchString(entry.Name()) && entry.Name() > newest {
			newest = entry.Name()
		}
	}
	if newest == "" {
		return "", nil
	}
	return filepath.Join(versionDir, newest), nil
}

func readManifest(dir, version string) ([]pkg, error) {
	b, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}
	base := "php" + version
	var recorded []pkg
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, ver, ok := strings.Cut(line, "\t")
		if !ok || !pkgRe.MatchString(name) || !pkgVerRe.MatchString(ver) || (name != base && !strings.HasPrefix(name, base+"-")) {
			return nil, fmt.Errorf("the backup's package list has a bad line: %q", line)
		}
		recorded = append(recorded, pkg{Name: name, Version: ver})
	}
	return recorded, nil
}

// Restore reinstalls a backup's exact packages and puts its config back. It
// is the rollback of Remove, so it also runs after Remove refused: when the
// recorded packages are all still installed it changes nothing, so an old
// backup can never overwrite live config.
func (e *Env) Restore(ctx context.Context, version, backup string) error {
	if err := e.checkHost(version); err != nil {
		return err
	}
	dir, err := e.findBackup(version, backup)
	if err != nil {
		return err
	}
	installed, err := e.packages(ctx, version)
	if err != nil {
		return err
	}
	if dir == "" {
		if len(installed) > 0 {
			e.say("PHP %s is installed and has no backup: nothing was removed, nothing to restore", version)
			return nil
		}
		return fmt.Errorf("no backup of PHP %s to restore", version)
	}
	recorded, err := readManifest(dir, version)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, p := range installed {
		present[p.Name] = true
	}
	missing := 0
	for _, p := range recorded {
		if !present[p.Name] {
			missing++
		}
	}
	if missing == 0 {
		e.say("Every package in %s is still installed: nothing to restore", dir)
		return nil
	}

	specs := make([]string, len(recorded))
	for i, p := range recorded {
		specs[i] = p.Name + "=" + p.Version
	}
	sim := append([]string{"/usr/bin/apt-get", "-s", "install", "--allow-downgrades", "--no-install-recommends"}, specs...)
	out, stderr, code, err := e.run(ctx, aptEnv, sim...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("can't reinstall the recorded versions (one may no longer be available), nothing was changed:\n%s", tail(stderr))
	}
	if removed, _ := simulatedChanges(out); len(removed) > 0 {
		return fmt.Errorf("refused: reinstalling would remove: %s", strings.Join(removed, ", "))
	}

	argv := append([]string{"/usr/bin/apt-get", "-q", "-y"}, aptOptions...)
	argv = append(append(argv, "install", "--allow-downgrades", "--no-install-recommends"), specs...)
	if err := e.stream(ctx, argv); err != nil {
		return fmt.Errorf("reinstall failed: %w", err)
	}
	now, err := e.packages(ctx, version)
	if err != nil {
		return err
	}
	versions := map[string]string{}
	for _, p := range now {
		versions[p.Name] = p.Version
	}
	for _, p := range recorded {
		if versions[p.Name] != p.Version {
			return fmt.Errorf("%s is at %q after the reinstall, not the recorded %s", p.Name, versions[p.Name], p.Version)
		}
	}

	tarball := filepath.Join(dir, configTar)
	if _, err := os.Stat(tarball); err == nil {
		if err := os.RemoveAll(e.path("/etc/php/" + version)); err != nil {
			return err
		}
		_, stderr, code, err := e.run(ctx, nil, "/usr/bin/tar", "-C", e.path("/etc/php"), "-xpf", tarball)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("restoring the config failed with status %d: %s", code, strings.TrimSpace(stderr))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// Remove only ran with FPM stopped and disabled; the package starts it.
	unit := "php" + version + "-fpm"
	if present, _ := findPkg(recorded, unit); present {
		_, stderr, code, err := e.run(ctx, nil, "/usr/bin/systemctl", "disable", "--now", unit)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("stopping %s failed with status %d: %s", unit, code, strings.TrimSpace(stderr))
		}
	}
	e.say("PHP %s is restored from %s", version, dir)
	return nil
}

func findPkg(ps []pkg, name string) (bool, string) {
	for _, p := range ps {
		if p.Name == name {
			return true, p.Version
		}
	}
	return false, ""
}
