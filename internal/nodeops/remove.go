package nodeops

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
	"syscall"

	"github.com/realmwatch/bifrost-agent/internal/phpops"
)

var removedRe = regexp.MustCompile(`^([0-9]{2})-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]{8}T[0-9]{6}Z)$`)

// Remove moves /opt/node/NN to /var/backups/node-remove, refusing while a
// running process, a supervisor, systemd or cron file, or a pm2 dump names
// it.
func (e *Env) Remove(ctx context.Context, major string) error {
	if err := checkMajor(major); err != nil {
		return err
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	dir := installDir(major)
	full := e.path(dir)
	if info, err := os.Lstat(full); err != nil || !info.IsDir() {
		return fmt.Errorf("refused: %s isn't installed", dir)
	}
	if pids := e.processesUnder(dir); len(pids) > 0 {
		return fmt.Errorf("refused: running processes use %s: %s", dir, strings.Join(pids, "; "))
	}
	if refs, err := e.referencesTo(dir); err != nil {
		return err
	} else if len(refs) > 0 {
		return fmt.Errorf("refused: these files name %s:\n%s", dir, strings.Join(refs, "\n"))
	}
	version, err := e.headerVersion(full)
	if err != nil {
		return err
	}
	backupDir := e.path(removeBackupRoot)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return err
	}
	dest := filepath.Join(backupDir, fmt.Sprintf("%s-v%s-%s", major, version, e.Now().UTC().Format(stampLayout)))
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("refused: %s already exists", e.host(dest))
	}
	if err := e.move(ctx, full, dest); err != nil {
		return fmt.Errorf("moving %s to %s failed: %w", dir, e.host(dest), err)
	}
	e.say("Node.js v%s is removed from %s. It is kept at %s; nodejs.restore puts it back.", version, dir, e.host(dest))
	return nil
}

// Restore moves the newest backup of NN back to /opt/node/NN. It is the
// rollback of Remove, so it also runs after Remove refused: when
// /opt/node/NN exists it changes nothing and succeeds, like php.restore.
func (e *Env) Restore(ctx context.Context, major string) error {
	if err := checkMajor(major); err != nil {
		return err
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	dir := installDir(major)
	full := e.path(dir)
	if _, err := os.Lstat(full); err == nil {
		e.say("%s is installed: nothing was removed, nothing to restore", dir)
		return nil
	}
	entries, err := os.ReadDir(e.path(removeBackupRoot))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	newest, stamp := "", ""
	for _, ent := range entries {
		m := removedRe.FindStringSubmatch(ent.Name())
		if m == nil || m[1] != major || !ent.IsDir() {
			continue
		}
		if m[3] > stamp || m[3] == stamp && ent.Name() > newest {
			newest, stamp = ent.Name(), m[3]
		}
	}
	if newest == "" {
		return fmt.Errorf("refused: no backup of Node.js %s under %s", major, removeBackupRoot)
	}
	if err := os.MkdirAll(e.path(InstallRoot), 0o755); err != nil {
		return err
	}
	src := filepath.Join(e.path(removeBackupRoot), newest)
	if err := e.move(ctx, src, full); err != nil {
		return fmt.Errorf("moving %s back failed: %w", e.host(src), err)
	}
	e.say("Restored %s from %s", dir, e.host(src))
	return nil
}

// move renames src to dest, or copies and removes it across filesystems.
func (e *Env) move(ctx context.Context, src, dest string) error {
	err := os.Rename(src, dest)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := e.check(ctx, "copying "+e.host(src), nil, "/usr/bin/cp", "-a", "--", src, dest); err != nil {
		os.RemoveAll(dest)
		return err
	}
	return os.RemoveAll(src)
}

// processesUnder lists running processes whose executable is under dir.
func (e *Env) processesUnder(dir string) []string {
	exes, _ := filepath.Glob(e.path("/proc/[0-9]*/exe"))
	sort.Strings(exes)
	var out []string
	for _, p := range exes {
		target, err := os.Readlink(p)
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, dir+"/") {
			pid := filepath.Base(filepath.Dir(p))
			out = append(out, fmt.Sprintf("PID %s runs %s", pid, strings.TrimSuffix(target, " (deleted)")))
		}
	}
	return out
}

// referencesTo lists config lines naming dir: supervisor, systemd (with
// drop-ins), cron and pm2 dumps.
func (e *Env) referencesTo(dir string) ([]string, error) {
	var files []string
	for _, g := range []string{"/etc/supervisor/conf.d/*", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/etc/crontab", "/root/.pm2/dump.pm2", "/home/*/.pm2/dump.pm2"} {
		paths, err := filepath.Glob(e.path(g))
		if err != nil {
			return nil, err
		}
		files = append(files, paths...)
	}
	err := filepath.WalkDir(e.path("/etc/systemd/system"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []string
	for _, p := range files {
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		pm2 := strings.HasSuffix(p, "/.pm2/dump.pm2")
		for i, line := range strings.Split(string(b), "\n") {
			if !pm2 && isComment(line) {
				continue
			}
			if phpops.MentionsRoot(line, dir) {
				out = append(out, fmt.Sprintf("%s:%d", e.host(p), i+1))
				if pm2 {
					break
				}
			}
		}
	}
	return out, nil
}
