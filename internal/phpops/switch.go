package phpops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const switchBackupRoot = "/var/backups/php-switch"

var rootRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// CheckRoot validates a site root from the hub: absolute, clean, no "..".
func CheckRoot(root string) error {
	if len(root) > 255 || !rootRe.MatchString(root) || filepath.Clean(root) != root || root == "/" || strings.Contains(root, "..") {
		return fmt.Errorf("bad site root %q", root)
	}
	return nil
}

// edit is one file Switch changes.
type edit struct {
	path    string // as on the host (without e.Root)
	real    string // the file written
	kind    string // nginx, cron, supervisor or systemd
	old     []byte
	new     []byte
	mode    os.FileMode
	uid     int
	gid     int
	changes int
}

// Switch moves one site from PHP from to PHP to: its nginx vhosts' FPM
// socket, then the cron, supervisor and systemd lines that run PHP for it.
// It never touches the host-wide php alternative. Every file is backed up
// first; if nginx -t, a reload or the smoke check fails, every file is put
// back and Switch fails. A site already on to is left alone, so a rollback
// after a failed switch (which already restored) succeeds.
func (e *Env) Switch(ctx context.Context, root, from, to string) error {
	if err := CheckRoot(root); err != nil {
		return err
	}
	if err := e.checkHost(from); err != nil {
		return err
	}
	if err := e.checkHost(to); err != nil {
		return err
	}
	if from == to {
		return errors.New("refused: from and to are the same version")
	}
	if info, err := os.Stat(e.path(root)); err != nil || !info.IsDir() {
		return fmt.Errorf("refused: %s isn't a directory on this host", root)
	}
	blocks, err := e.serverBlocks()
	if err != nil {
		return err
	}
	var mine []serverBlock
	for _, b := range blocks {
		if b.appRoot == root {
			mine = append(mine, b)
		}
	}
	if len(mine) == 0 {
		return fmt.Errorf("refused: no enabled nginx vhost serves %s", root)
	}
	names := []string{}
	onFrom, onTo := false, false
	for _, b := range mine {
		onFrom = onFrom || b.php == from
		onTo = onTo || b.php == to
		for _, n := range b.names {
			if !contains(names, n) {
				names = append(names, n)
			}
		}
	}

	// Once nginx serves the site on to, a bare php is no longer the site's
	// old version, so only lines naming from explicitly still move.
	cliEdits := e.cliEdits(root, from, to, onFrom)
	if !onFrom {
		if onTo && len(cliEdits) == 0 {
			e.say("%s already runs on PHP %s and no cron, supervisor or systemd line names PHP %s for it: nothing to do", root, to, from)
			return nil
		}
		if !onTo {
			return fmt.Errorf("refused: nginx doesn't serve %s with php%s-fpm", root, from)
		}
	}
	if !e.unitIs(ctx, "is-active", "php"+to+"-fpm") {
		return fmt.Errorf("refused: php%s-fpm isn't running; install PHP %s first", to, to)
	}

	vhostEdits, err := vhostEdits(mine, from, to, e.Root)
	if err != nil {
		return err
	}
	edits := append(vhostEdits, cliEdits...)
	dir, err := e.switchBackup(edits)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %d files to %s", len(edits), dir)
	logPath := e.path("/var/log/php" + to + "-fpm.log")
	logStart := fileSize(logPath)

	fail := func(cause error) error {
		if err := e.putBack(ctx, edits); err != nil {
			return fmt.Errorf("%w; putting the files back failed too (backup in %s): %v", cause, dir, err)
		}
		return fmt.Errorf("%w; every file was put back (backup in %s)", cause, dir)
	}

	for _, ed := range vhostEdits {
		if err := writeLike(ed, ed.new); err != nil {
			return fail(err)
		}
		e.say("%s: %d line(s) now use php%s-fpm", ed.path, ed.changes, to)
	}
	if len(vhostEdits) > 0 {
		if err := e.check(ctx, "nginx -t", "/usr/sbin/nginx", "-t"); err != nil {
			return fail(err)
		}
		if err := e.check(ctx, "reloading nginx", "/usr/bin/systemctl", "reload", "nginx"); err != nil {
			return fail(err)
		}
	}
	if err := e.applyCLI(ctx, cliEdits, to); err != nil {
		return fail(err)
	}

	if len(names) == 0 {
		e.say("The vhost has no server_name, so there's no HTTP smoke check")
	} else if err := e.smoke(ctx, names[0]); err != nil {
		return fail(err)
	}
	if bad := newLogErrors(logPath, logStart); len(bad) > 0 {
		return fail(fmt.Errorf("php%s-fpm logged errors after the switch:\n%s", to, strings.Join(bad, "\n")))
	}
	e.say("%s now runs on PHP %s. The php command for the rest of the host is unchanged.", root, to)
	return nil
}

// vhostEdits rewrites the FPM socket inside this site's server blocks only.
func vhostEdits(mine []serverBlock, from, to, hostRoot string) ([]edit, error) {
	byFile := map[string][]serverBlock{}
	var order []string
	for _, b := range mine {
		if _, ok := byFile[b.real]; !ok {
			order = append(order, b.real)
		}
		byFile[b.real] = append(byFile[b.real], b)
	}
	sort.Strings(order)
	var out []edit
	for _, real := range order {
		ed, err := readEdit(real, strings.TrimPrefix(real, hostRoot), "nginx")
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(ed.old), "\n")
		for _, b := range byFile[real] {
			for i := b.start; i <= b.end && i < len(lines); i++ {
				if isComment(lines[i]) || !strings.Contains(lines[i], "fastcgi_pass") {
					continue
				}
				if n := strings.ReplaceAll(lines[i], "php"+from+"-fpm", "php"+to+"-fpm"); n != lines[i] {
					lines[i] = n
					ed.changes++
				}
			}
		}
		if ed.changes > 0 {
			ed.new = []byte(strings.Join(lines, "\n"))
			out = append(out, ed)
		}
	}
	return out, nil
}

// cliEdits rewrites the PHP in cron, supervisor and systemd lines that
// mention the site root: php{from}, /usr/bin/php{from} and a bare php all
// become php{to}. Other versions are left alone.
func (e *Env) cliEdits(root, from, to string, bare bool) []edit {
	var out []edit
	for _, f := range e.cliFiles() {
		changed := 0
		lines := append([]string{}, f.lines...)
		for i, line := range lines {
			if isComment(line) || !mentionsRoot(line, root) {
				continue
			}
			n := phpCallRe.ReplaceAllStringFunc(line, func(m string) string {
				sub := phpCallRe.FindStringSubmatch(m)
				if sub[3] != from && (sub[3] != "" || !bare) {
					return m
				}
				return sub[1] + sub[2] + to + sub[4]
			})
			if n != line {
				lines[i] = n
				changed++
			}
		}
		if changed == 0 {
			continue
		}
		ed, err := readEdit(f.real, f.path, f.kind)
		if err != nil {
			continue
		}
		ed.new, ed.changes = []byte(strings.Join(lines, "\n")), changed
		out = append(out, ed)
	}
	return out
}

func readEdit(real, path, kind string) (edit, error) {
	info, err := os.Lstat(real)
	if err != nil {
		return edit{}, err
	}
	b, err := os.ReadFile(real)
	if err != nil {
		return edit{}, err
	}
	ed := edit{path: path, real: real, kind: kind, old: b, mode: info.Mode().Perm(), uid: -1, gid: -1}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ed.uid, ed.gid = int(st.Uid), int(st.Gid)
	}
	return ed, nil
}

// writeLike replaces the file's content in place of a temporary file in
// the same directory, keeping its mode and owner.
func writeLike(ed edit, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(ed.real), ".bifrost-php-switch-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(ed.mode); err != nil {
		return cleanup(err)
	}
	if ed.uid >= 0 {
		if err := tmp.Chown(ed.uid, ed.gid); err != nil {
			return cleanup(err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, ed.real); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (e *Env) switchBackup(edits []edit) (string, error) {
	root := e.path(switchBackupRoot)
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
			break
		}
		if !errors.Is(err, os.ErrExist) || i > 100 {
			return "", err
		}
		dir = filepath.Join(root, fmt.Sprintf("%s-%d", stamp, i))
	}
	var manifest strings.Builder
	for i, ed := range edits {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)), ed.old, 0o600); err != nil {
			return "", err
		}
		fmt.Fprintf(&manifest, "%d\t%s\t%04o\t%d\t%d\n", i, ed.path, ed.mode, ed.uid, ed.gid)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.tsv"), []byte(manifest.String()), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func (e *Env) applyCLI(ctx context.Context, edits []edit, to string) error {
	supervisor, units := false, []string{}
	for _, ed := range edits {
		if err := writeLike(ed, ed.new); err != nil {
			return err
		}
		e.say("%s: %d line(s) now run php%s", ed.path, ed.changes, to)
		switch ed.kind {
		case "supervisor":
			supervisor = true
		case "systemd":
			units = append(units, filepath.Base(ed.path))
		}
	}
	return e.reloadCLI(ctx, supervisor, units)
}

func (e *Env) reloadCLI(ctx context.Context, supervisor bool, units []string) error {
	if supervisor {
		if err := e.check(ctx, "supervisorctl reread", "/usr/bin/supervisorctl", "reread"); err != nil {
			return err
		}
		if err := e.check(ctx, "supervisorctl update", "/usr/bin/supervisorctl", "update"); err != nil {
			return err
		}
	}
	if len(units) > 0 {
		if err := e.check(ctx, "systemctl daemon-reload", "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		for _, u := range units {
			if err := e.check(ctx, "restarting "+u, "/usr/bin/systemctl", "restart", u); err != nil {
				return err
			}
		}
	}
	return nil
}

// putBack restores every edited file and reloads what reads them.
func (e *Env) putBack(ctx context.Context, edits []edit) error {
	var errs []error
	nginx, supervisor, units := false, false, []string{}
	for _, ed := range edits {
		if err := writeLike(ed, ed.old); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ed.path, err))
			continue
		}
		switch ed.kind {
		case "nginx":
			nginx = true
		case "supervisor":
			supervisor = true
		case "systemd":
			units = append(units, filepath.Base(ed.path))
		}
	}
	if nginx {
		if err := e.check(ctx, "nginx -t", "/usr/sbin/nginx", "-t"); err != nil {
			errs = append(errs, err)
		} else if err := e.check(ctx, "reloading nginx", "/usr/bin/systemctl", "reload", "nginx"); err != nil {
			errs = append(errs, err)
		}
	}
	if err := e.reloadCLI(ctx, supervisor, units); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (e *Env) check(ctx context.Context, what string, argv ...string) error {
	_, stderr, code, err := e.run(ctx, nil, argv...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s failed with status %d:\n%s", what, code, tail(stderr))
	}
	return nil
}

// smoke asks nginx on this host for the site's front page: HTTPS first,
// then HTTP. A 5xx or no answer at all fails.
func (e *Env) smoke(ctx context.Context, name string) error {
	for _, try := range []struct{ port, url string }{{"443", "https://" + name + "/"}, {"80", "http://" + name + "/"}} {
		out, _, code, err := e.run(ctx, nil, "/usr/bin/curl", "-sS", "-k", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20",
			"--resolve", name+":"+try.port+":127.0.0.1", try.url)
		if err != nil {
			return err
		}
		status, _ := strconv.Atoi(strings.TrimSpace(out))
		if code != 0 || status == 0 {
			continue
		}
		if status >= 500 {
			return fmt.Errorf("smoke check: %s answered HTTP %d", try.url, status)
		}
		e.say("Smoke check: %s answered HTTP %d", try.url, status)
		return nil
	}
	return fmt.Errorf("smoke check: nginx on this host didn't answer for %s on 443 or 80", name)
}

func fileSize(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.Size()
}

// newLogErrors returns ERROR and ALERT lines written after offset.
func newLogErrors(p string, offset int64) []string {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() < offset {
		offset = 0 // rotated
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil
	}
	var bad []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "ERROR:") || strings.Contains(line, "ALERT:") {
			bad = append(bad, line)
		}
	}
	if len(bad) > 10 {
		bad = bad[:10]
	}
	return bad
}
