package phpops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const installBackupRoot = "/var/backups/php-install"

// PortedIni is the override file Install writes with the php.ini settings
// the old version changed from its own defaults.
const PortedIni = "99-bifrost-ported.ini"

// portedSettings are the php.ini settings hosts commonly tune (Forge
// writes most of them into php.ini itself). Install copies the old
// version's value of each into an override file when it differs from the
// new version's php.ini. Everything else in php.ini keeps the new
// version's defaults, which change between versions on purpose.
var portedSettings = []string{
	"date.timezone", "display_errors", "max_execution_time", "max_file_uploads", "max_input_time",
	"max_input_vars", "memory_limit", "opcache.enable", "opcache.enable_cli", "opcache.max_accelerated_files",
	"opcache.memory_consumption", "opcache.revalidate_freq", "opcache.validate_timestamps", "post_max_size",
	"upload_max_filesize",
}

// mergedExtensions became part of PHP itself in 8.0, so 8.x has no package.
var mergedExtensions = map[string]bool{"json": true}

var (
	listenRe  = regexp.MustCompile(`^\s*listen\s*=\s*(\S+)`)
	iniLineRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$`)
)

// Install installs PHP version alongside like: its FPM, CLI and the
// counterpart of every php{like}-* package, then ports like's FPM pools
// and config overrides, and starts the new FPM. No site is switched.
func (e *Env) Install(ctx context.Context, version, like string) error {
	if err := e.checkHost(version); err != nil {
		return err
	}
	if err := e.checkHost(like); err != nil {
		return err
	}
	if version == like {
		return errors.New("refused: the new version is the one installed")
	}
	have, err := e.packages(ctx, version)
	if err != nil {
		return err
	}
	if ok, _ := findPkg(have, "php"+version+"-fpm"); ok {
		return fmt.Errorf("refused: php%s-fpm is already installed", version)
	}
	old, err := e.packages(ctx, like)
	if err != nil {
		return err
	}
	if len(old) == 0 {
		return fmt.Errorf("refused: no php%s packages are installed to copy", like)
	}
	want, skipped := counterparts(old, like, version)
	pools, err := e.pools(like, version)
	if err != nil {
		return err
	}

	cands, err := e.candidates(ctx, want)
	if err != nil {
		return err
	}
	var missing []string
	for _, n := range want {
		if _, ok := cands[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("refused: apt has no package for: %s. Install PHP %s by hand without them if the sites don't need them", strings.Join(missing, ", "), version)
	}
	out, stderr, code, err := e.run(ctx, aptEnv, append([]string{"/usr/bin/apt-get", "-s", "install", "--no-install-recommends"}, want...)...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("refused: the install simulation exited with status %d:\n%s", code, tail(stderr))
	}
	if removed, _ := simulatedChanges(out); len(removed) > 0 {
		sort.Strings(removed)
		return fmt.Errorf("refused: installing would remove: %s", strings.Join(removed, ", "))
	}
	e.say("Installing PHP %s like %s: %s", version, like, strings.Join(want, " "))
	if len(skipped) > 0 {
		e.say("Not needed on PHP %s (built in): %s", version, strings.Join(skipped, ", "))
	}

	before := e.alternatives()
	argv := append([]string{"/usr/bin/apt-get", "-q", "-y"}, aptOptions...)
	argv = append(append(argv, "install", "--no-install-recommends"), want...)
	installErr := e.stream(ctx, argv)
	// The new CLI's alternatives have a higher priority, so in auto mode
	// apt points the host-wide php at it. Put back whatever was there,
	// even when the install failed partway.
	if err := e.restoreAlternatives(ctx, before); err != nil {
		if installErr != nil {
			return fmt.Errorf("install failed: %w; and %v", installErr, err)
		}
		return err
	}
	if installErr != nil {
		return fmt.Errorf("install failed: %w", installErr)
	}

	dir, err := e.installBackup(version)
	if err != nil {
		return fmt.Errorf("backing up the new pools failed: %w", err)
	}
	if err := e.portPools(version, pools); err != nil {
		return fmt.Errorf("porting the pools failed (the packaged ones are in %s): %w", dir, err)
	}
	for _, sapi := range []string{"fpm", "cli"} {
		if err := e.portOverrides(like, version, sapi); err != nil {
			return fmt.Errorf("porting the %s overrides failed: %w", sapi, err)
		}
	}

	unit := "php" + version + "-fpm"
	_, stderr, code, err = e.run(ctx, nil, "/usr/sbin/php-fpm"+version, "-t")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("php-fpm%s -t failed with status %d:\n%s", version, code, tail(stderr))
	}
	_, stderr, code, err = e.run(ctx, nil, "/usr/bin/systemctl", "enable", "--now", unit)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("starting %s failed with status %d: %s", unit, code, strings.TrimSpace(stderr))
	}
	if !e.unitIs(ctx, "is-active", unit) {
		return fmt.Errorf("%s isn't active after starting it", unit)
	}
	e.say("PHP %s is installed and %s is running. No site uses it yet.", version, unit)
	return nil
}

// counterparts maps the installed php{like}-* packages to php{version}-*,
// always with fpm and cli, sorted. Extensions built into the new version
// are returned separately.
func counterparts(old []pkg, like, version string) (want, skipped []string) {
	set := map[string]bool{"php" + version + "-fpm": true, "php" + version + "-cli": true}
	newMajor, _ := splitVersion(version)
	for _, p := range old {
		suffix, ok := strings.CutPrefix(p.Name, "php"+like+"-")
		if !ok {
			continue // the bare metapackage pulls in a web server module
		}
		if mergedExtensions[suffix] && newMajor >= 8 {
			skipped = append(skipped, p.Name)
			continue
		}
		set["php"+version+"-"+suffix] = true
	}
	for n := range set {
		want = append(want, n)
	}
	sort.Strings(want)
	return want, skipped
}

type pool struct {
	name    string
	content string
	mode    fs.FileMode
}

// pools reads like's FPM pools, rewritten for version. A pool listening
// on a TCP port would clash with the old one, so it refuses.
func (e *Env) pools(like, version string) ([]pool, error) {
	paths, err := filepath.Glob(e.path("/etc/php/" + like + "/fpm/pool.d/*.conf"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []pool
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if m := listenRe.FindStringSubmatch(line); m != nil && !strings.HasPrefix(m[1], "/") {
				return nil, fmt.Errorf("refused: pool %s listens on %s, which the new FPM would clash with; give it a socket first", filepath.Base(p), m[1])
			}
		}
		content := strings.ReplaceAll(string(b), "php"+like+"-fpm", "php"+version+"-fpm")
		out = append(out, pool{name: filepath.Base(p), content: content, mode: info.Mode().Perm()})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("refused: PHP %s has no FPM pools to copy", like)
	}
	return out, nil
}

func (e *Env) installBackup(version string) (string, error) {
	root := e.path(filepath.Join(installBackupRoot, version))
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	dir := filepath.Join(root, e.Now().UTC().Format(stampLayout))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	src := e.path("/etc/php/" + version + "/fpm/pool.d")
	entries, err := os.ReadDir(src)
	if errors.Is(err, fs.ErrNotExist) {
		return dir, nil
	}
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(filepath.Join(dir, "pool.d"), 0o700); err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, "pool.d", entry.Name()), b, 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// portPools replaces the new version's packaged pools with the ported ones.
func (e *Env) portPools(version string, pools []pool) error {
	dir := e.path("/etc/php/" + version + "/fpm/pool.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	old, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		return err
	}
	for _, p := range old {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	for _, p := range pools {
		if err := os.WriteFile(filepath.Join(dir, p.name), []byte(p.content), p.mode); err != nil {
			return err
		}
		e.say("Ported pool %s", p.name)
	}
	return nil
}

// portOverrides copies like's own conf.d files (not the packages' links)
// and the tuned php.ini settings that differ from the new version's.
func (e *Env) portOverrides(like, version, sapi string) error {
	src := e.path("/etc/php/" + like + "/" + sapi + "/conf.d")
	dst := e.path("/etc/php/" + version + "/" + sapi + "/conf.d")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() == PortedIni {
			continue
		}
		target := filepath.Join(dst, entry.Name())
		if _, err := os.Lstat(target); err == nil {
			e.say("Kept %s's own %s/conf.d/%s", version, sapi, entry.Name())
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return err
		}
		e.say("Copied %s/conf.d/%s", sapi, entry.Name())
	}

	oldIni := iniValues(e.path("/etc/php/" + like + "/" + sapi + "/php.ini"))
	newIni := iniValues(e.path("/etc/php/" + version + "/" + sapi + "/php.ini"))
	var b strings.Builder
	for _, k := range portedSettings {
		v, ok := oldIni[k]
		if !ok || newIni[k] == v {
			continue
		}
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	if b.Len() == 0 {
		return nil
	}
	content := fmt.Sprintf("; Settings PHP %s's %s php.ini changed, ported by bifrost-agent.\n%s", like, sapi, b.String())
	if err := os.WriteFile(filepath.Join(dst, PortedIni), []byte(content), 0o644); err != nil {
		return err
	}
	e.say("Ported %s php.ini settings into %s/conf.d/%s:\n%s", sapi, sapi, PortedIni, strings.TrimSpace(b.String()))
	return nil
}

// iniValues reads the settings a php.ini sets (comments ignored).
func iniValues(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if isComment(line) {
			continue
		}
		if m := iniLineRe.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

// phpAlternatives are the alternatives PHP's packages register.
var phpAlternatives = []string{"php", "phar", "phar.phar", "php-config", "phpize", "php-cgi"}

// alternatives records where each PHP alternative points now.
func (e *Env) alternatives() map[string]string {
	out := map[string]string{}
	for _, name := range phpAlternatives {
		if target, err := os.Readlink(e.path("/etc/alternatives/" + name)); err == nil {
			out[name] = target
		}
	}
	return out
}

// restoreAlternatives points every alternative recorded in before back at
// its old target if the install moved it.
func (e *Env) restoreAlternatives(ctx context.Context, before map[string]string) error {
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		now, _ := os.Readlink(e.path("/etc/alternatives/" + name))
		if now == before[name] {
			continue
		}
		_, stderr, code, err := e.run(ctx, nil, "/usr/bin/update-alternatives", "--set", name, before[name])
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("putting the %s alternative back to %s failed with status %d: %s", name, before[name], code, strings.TrimSpace(stderr))
		}
		e.say("Put the %s alternative back to %s (installing had moved it to %s)", name, before[name], orUnknown(now))
	}
	return nil
}
