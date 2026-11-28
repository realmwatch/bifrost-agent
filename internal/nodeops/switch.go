package nodeops

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/filebackup"
	"github.com/realmwatch/bifrost-agent/internal/phpops"
)

const rebuildTimeout = 10 * time.Minute

// fileEdit is one file SwitchSite changes.
type fileEdit struct {
	path    string // host path
	real    string
	kind    string
	lines   []string
	changes int
	names   map[string]bool // the programs or units it changed
}

// switchManifest is the backup's manifest.
type switchManifest struct {
	Root        string              `json:"root"`
	From        string              `json:"from"`
	To          string              `json:"to"`
	Entries     []filebackup.Entry  `json:"entries"`
	NodeModules bool                `json:"node_modules"`
	Changed     map[string][]string `json:"changed"`
}

// underRoot says whether service s belongs to root: a cron line, or a
// supervisor program or unit whose command or directory names a path
// under root.
func underRoot(s service, i int, root string) bool {
	if s.kind == "cron" {
		return phpops.MentionsRoot(s.lines[i], root)
	}
	for j := s.start; j <= s.end; j++ {
		if (s.cmdLine(j) || s.dirLine(j)) && phpops.MentionsRoot(s.lines[j], root) {
			return true
		}
	}
	return false
}

// lineRuns says whether command line i of s runs bin.
func (e *Env) lineRuns(s service, i int, bin string) bool {
	if len(tokenAt(s.lines[i], bin, beforePathDelims)) > 0 {
		return true
	}
	return bin == DefaultNode && len(tokenAt(s.lines[i], "node", beforeDelims)) > 0 && e.resolveBare(s.pathDirs()) == DefaultNode
}

// SwitchSite moves the supervisor programs, systemd units and cron lines
// of the site at root from node binary from to to. Every file is backed
// up first; on any failure everything is put back.
func (e *Env) SwitchSite(ctx context.Context, root, from, to string) error {
	if err := phpops.CheckRoot(root); err != nil {
		return err
	}
	for _, b := range []string{from, to} {
		if len(b) > 255 || !BinaryRe.MatchString(b) {
			return fmt.Errorf("bad node binary %q", b)
		}
	}
	if from == to {
		return errors.New("refused: from and to are the same binary")
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	info, err := os.Stat(e.path(root))
	if err != nil || !info.IsDir() {
		return fmt.Errorf("refused: %s isn't a directory on this host", root)
	}
	if bi, err := os.Stat(e.path(to)); err != nil || !bi.Mode().IsRegular() || bi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("refused: %s doesn't exist or isn't executable; install it first", to)
	}

	fromDir, toDir := filepath.Dir(from), filepath.Dir(to)
	byFile := map[string]*fileEdit{}
	var order []string
	onTo := 0
	for _, s := range e.services() {
		ed := byFile[s.real]
		lines := s.lines
		if ed != nil {
			lines = ed.lines
		}
		changed := false
		for i := s.start; i <= s.end; i++ {
			if !s.cmdLine(i) || !underRoot(s, i, root) {
				continue
			}
			if e.lineRuns(s, i, to) {
				onTo++
			}
			if !e.lineRuns(s, i, from) {
				continue
			}
			if err := checkName(s); err != nil {
				return err
			}
			n, c := replaceToken(lines[i], from, to, beforePathDelims)
			if from == DefaultNode {
				var c2 int
				n, c2 = replaceToken(n, "node", to, beforeDelims)
				c += c2
			}
			if c > 0 {
				lines = cloneOnce(lines, s.lines)
				lines[i] = n
				changed = true
			}
		}
		if !changed {
			continue
		}
		// The same program's or unit's PATH moves with it.
		for i := s.start; i <= s.end; i++ {
			if s.envLine(i) {
				if n, ok := rewritePath(lines[i], fromDir, toDir); ok {
					lines[i] = n
				}
			}
		}
		if ed == nil {
			ed = &fileEdit{path: s.path, real: s.real, kind: s.kind, names: map[string]bool{}}
			byFile[s.real] = ed
			order = append(order, s.real)
		}
		ed.lines = lines
		ed.changes++
		if s.name != "" {
			ed.names[s.name] = true
		}
	}
	// A unit's drop-ins carry its PATH too.
	e.dropInPaths(byFile, &order, fromDir, toDir)

	if len(order) == 0 {
		if onTo > 0 {
			e.say("Nothing under %s runs %s and %d line(s) already run %s: already moved, nothing to do", root, from, onTo, to)
			return nil
		}
		if pm2 := e.pm2Names(root); len(pm2) > 0 {
			return fmt.Errorf("refused: only pm2 runs %s (%s), and this operation doesn't move pm2 processes; change the pm2 ecosystem by hand", root, strings.Join(pm2, ", "))
		}
		return fmt.Errorf("refused: no supervisor program, systemd unit or cron line under %s runs %s", root, from)
	}
	if pm2 := e.pm2Names(root); len(pm2) > 0 {
		e.say("Note: pm2 also runs %s (%s); its processes aren't moved", root, strings.Join(pm2, ", "))
	}
	sort.Strings(order)

	edits := make([]*fileEdit, len(order))
	for i, real := range order {
		edits[i] = byFile[real]
	}
	native, err := hasNativeModules(e.path(filepath.Join(root, "node_modules")))
	if err != nil {
		return err
	}

	dir, m, err := e.switchBackup(ctx, root, from, to, edits, native)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %d file(s) to %s", len(edits), e.host(dir))

	supervisor := false
	var changed []target
	for _, ed := range edits {
		if ed.kind == "supervisor" {
			supervisor = true
		}
		if ed.kind == "supervisor" || ed.kind == "systemd" {
			for n := range ed.names {
				changed = appendTarget(changed, target{kind: ed.kind, name: n})
			}
		}
	}
	// Only what runs now is restarted and checked: a stopped program or
	// unit stays stopped.
	targets, err := e.running(ctx, changed)
	if err != nil {
		return err
	}
	units := []string{}
	for _, t := range targets {
		if t.kind == "systemd" {
			units = append(units, t.name)
		}
	}
	systemd := false
	for _, t := range changed {
		systemd = systemd || t.kind == "systemd"
	}

	fail := func(cause error) error {
		if err := e.putBack(ctx, root, dir, m, supervisor, systemd, units); err != nil {
			return fmt.Errorf("%w; putting everything back failed too (backup in %s): %v", cause, e.host(dir), err)
		}
		return fmt.Errorf("%w; every file was put back (backup in %s)", cause, e.host(dir))
	}

	for _, ed := range edits {
		if err := writeEdit(ed); err != nil {
			return fail(err)
		}
		e.say("%s: %d program(s), unit(s) or line(s) now run %s", ed.path, ed.changes, to)
	}
	if native {
		if err := e.rebuild(ctx, root, toDir); err != nil {
			return fail(err)
		}
	}
	if err := e.reload(ctx, supervisor, systemd, units); err != nil {
		return fail(err)
	}
	if err := e.healthyAfterReload(ctx, targets); err != nil {
		return fail(err)
	}
	e.say("%s now runs %s", root, to)
	return nil
}

func cloneOnce(lines, orig []string) []string {
	if len(lines) > 0 && len(orig) > 0 && &lines[0] == &orig[0] {
		return append([]string{}, lines...)
	}
	return lines
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// dropInPaths moves the PATH in drop-ins of units the switch changes.
func (e *Env) dropInPaths(byFile map[string]*fileEdit, order *[]string, fromDir, toDir string) {
	units := map[string]bool{}
	for _, ed := range byFile {
		if ed.kind == "systemd" {
			for n := range ed.names {
				units[n] = true
			}
		}
	}
	for _, s := range e.services() {
		if s.kind != "systemd" || !units[s.name] {
			continue
		}
		ed := byFile[s.real]
		lines := s.lines
		if ed != nil {
			lines = ed.lines
		}
		changed := false
		for i := range lines {
			if s.envLine(i) {
				if n, ok := rewritePath(lines[i], fromDir, toDir); ok {
					lines = cloneOnce(lines, s.lines)
					lines[i] = n
					changed = true
				}
			}
		}
		if !changed {
			continue
		}
		if ed == nil {
			ed = &fileEdit{path: s.path, real: s.real, kind: s.kind, names: map[string]bool{s.name: true}}
			byFile[s.real] = ed
			*order = append(*order, s.real)
		}
		ed.lines = lines
	}
}

// pm2Names lists the pm2 dumps that name root.
func (e *Env) pm2Names(root string) []string {
	paths, _ := filepath.Glob(e.path("/home/*/.pm2/dump.pm2"))
	if p := e.path("/root/.pm2/dump.pm2"); fileExists(p) {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []string
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil && phpops.MentionsRoot(string(b), root) {
			out = append(out, e.host(p))
		}
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// hasNativeModules says whether node_modules holds a compiled addon.
func hasNativeModules(dir string) (bool, error) {
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".node") && d.Type().IsRegular() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}

func (e *Env) switchBackup(ctx context.Context, root, from, to string, edits []*fileEdit, native bool) (string, *switchManifest, error) {
	dir, err := filebackup.NewDir(e.Root, switchBackupRoot, e.Now())
	if err != nil {
		return "", nil, err
	}
	m := &switchManifest{Root: root, From: from, To: to, Changed: map[string][]string{}}
	for i, ed := range edits {
		en, err := filebackup.Save(e.Root, dir, strconv.Itoa(i), ed.path, ed.kind)
		if err != nil {
			return "", nil, err
		}
		m.Entries = append(m.Entries, en)
		for n := range ed.names {
			m.Changed[ed.path] = append(m.Changed[ed.path], n)
		}
		sort.Strings(m.Changed[ed.path])
	}
	if native {
		if err := e.check(ctx, "copying node_modules into the backup", nil, "/usr/bin/cp", "-a", "--", e.path(filepath.Join(root, "node_modules")), filepath.Join(dir, "node_modules")); err != nil {
			return "", nil, err
		}
		m.NodeModules = true
	}
	if err := filebackup.WriteManifest(dir, m); err != nil {
		return "", nil, err
	}
	return dir, m, nil
}

// writeEdit writes an edited file in place of the old, keeping mode and
// owner; a user's crontab stays 0600.
func writeEdit(ed *fileEdit) error {
	info, err := os.Lstat(ed.real)
	if err != nil {
		return err
	}
	mode, uid, gid := uint32(info.Mode().Perm()), -1, -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	if strings.Contains(ed.path, "/var/spool/cron/crontabs/") {
		mode = 0o600
	}
	return filebackup.WriteLike(ed.real, mode, uid, gid, []byte(strings.Join(ed.lines, "\n")))
}

// owner finds root's owner and home in /etc/passwd.
func (e *Env) owner(root string) (name, home string, err error) {
	info, err := os.Stat(e.path(root))
	if err != nil {
		return "", "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", errors.New("can't read the site root's owner")
	}
	f, err := os.Open(e.path("/etc/passwd"))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		p := strings.Split(lines.Text(), ":")
		if len(p) >= 6 && p[2] == strconv.Itoa(int(st.Uid)) && programNameRe.MatchString(p[0]) && strings.HasPrefix(p[5], "/") {
			return p[0], p[5], nil
		}
	}
	return "", "", fmt.Errorf("refused: %s's owner (uid %d) isn't in /etc/passwd", root, st.Uid)
}

// rebuild runs npm rebuild in root as its owner, with the new node first
// on PATH.
func (e *Env) rebuild(ctx context.Context, root, toDir string) error {
	user, home, err := e.owner(root)
	if err != nil {
		return err
	}
	e.say("node_modules holds native addons: running npm rebuild in %s as %s", root, user)
	ctx, cancel := context.WithTimeout(ctx, rebuildTimeout)
	defer cancel()
	argv := []string{"/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env", "-C", e.path(root), "HOME=" + home,
		"PATH=" + toDir + ":/usr/bin:/bin", toDir + "/npm", "rebuild"}
	if err := e.stream(ctx, "npm rebuild", argv...); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("npm rebuild took longer than %s", rebuildTimeout)
		}
		return err
	}
	return nil
}

// reload makes supervisor and systemd read the changed files and restart
// what changed.
func (e *Env) reload(ctx context.Context, supervisor, systemd bool, units []string) error {
	if supervisor {
		if err := e.check(ctx, "supervisorctl reread", nil, "/usr/bin/supervisorctl", "reread"); err != nil {
			return err
		}
		if err := e.check(ctx, "supervisorctl update", nil, "/usr/bin/supervisorctl", "update"); err != nil {
			return err
		}
	}
	if systemd {
		if err := e.check(ctx, "systemctl daemon-reload", nil, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		for _, u := range units {
			if err := e.check(ctx, "restarting "+u, nil, "/usr/bin/systemctl", "restart", u); err != nil {
				return err
			}
		}
	}
	return nil
}

// healthyAfterReload records the units' restart counts, then checks.
func (e *Env) healthyAfterReload(ctx context.Context, targets []target) error {
	for i := range targets {
		if targets[i].kind == "systemd" {
			props, err := e.unitProps(ctx, targets[i].name)
			if err != nil {
				return err
			}
			targets[i].restarts = props["NRestarts"]
		}
	}
	return e.healthy(ctx, targets)
}

// putBack restores every file and node_modules, then reloads.
func (e *Env) putBack(ctx context.Context, root, dir string, m *switchManifest, supervisor, systemd bool, units []string) error {
	var errs []error
	if err := filebackup.Restore(e.Root, m.Entries, dir, nil); err != nil {
		errs = append(errs, err)
	}
	if m.NodeModules {
		nm := e.path(filepath.Join(root, "node_modules"))
		aside := nm + ".bifrost-failed"
		os.RemoveAll(aside)
		if err := os.Rename(nm, aside); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		} else if err := e.check(ctx, "putting node_modules back", nil, "/usr/bin/cp", "-a", "--", filepath.Join(dir, "node_modules"), nm); err != nil {
			errs = append(errs, err)
		} else {
			os.RemoveAll(aside)
		}
	}
	if err := e.reload(ctx, supervisor, systemd, units); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		_ = filebackup.MarkRestored(dir, e.Now(), "the switch failed")
	}
	return errors.Join(errs...)
}
