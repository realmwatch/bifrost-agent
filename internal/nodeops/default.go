package nodeops

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/realmwatch/bifrost-agent/internal/filebackup"
)

// NodeSource's apt source, one-line or deb822.
var nodesourceFiles = []string{"/etc/apt/sources.list.d/nodesource.list", "/etc/apt/sources.list.d/nodesource.sources"}

var (
	nodesourceRe = regexp.MustCompile(`deb\.nodesource\.com/node_([0-9]+)\.x`)
	debVersionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:_-]*$`)
)

// defaultManifest is the default switch's backup manifest.
type defaultManifest struct {
	From    string             `json:"from"`
	To      string             `json:"to"`
	Nodejs  string             `json:"nodejs"`
	Entries []filebackup.Entry `json:"entries"`
}

// nodesourceSource finds NodeSource's source file and the majors it names.
func (e *Env) nodesourceSource() (path string, content string, majors map[string]bool, err error) {
	for _, p := range nodesourceFiles {
		b, err := os.ReadFile(e.path(p))
		if err != nil {
			continue
		}
		majors = map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			if isComment(line) {
				continue
			}
			for _, m := range nodesourceRe.FindAllStringSubmatch(line, -1) {
				majors[m[1]] = true
			}
		}
		return p, string(b), majors, nil
	}
	return "", "", nil, fmt.Errorf("refused: no NodeSource apt source (%s)", strings.Join(nodesourceFiles, " or "))
}

// nodejsVersion is the installed nodejs package's version, or "".
func (e *Env) nodejsVersion(ctx context.Context) (string, error) {
	out, _, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Version}\n", "nodejs")
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", nil
	}
	status, version, _ := strings.Cut(strings.TrimSpace(out), "\t")
	if len(status) < 2 || status[1] != 'i' {
		return "", nil
	}
	return version, nil
}

// DefaultSwitch moves the host's NodeSource nodejs from major from to to:
// it points the apt source at node_TO.x and installs nodejs from it, then
// restarts what runs /usr/bin/node. On any failure it puts the source and
// the recorded package version back.
func (e *Env) DefaultSwitch(ctx context.Context, from, to string) error {
	if err := checkMajor(from); err != nil {
		return err
	}
	if err := checkMajor(to); err != nil {
		return err
	}
	if from == to {
		return fmt.Errorf("refused: from and to are the same major")
	}
	if err := e.checkHost(); err != nil {
		return err
	}
	src, content, majors, err := e.nodesourceSource()
	if err != nil {
		return err
	}
	current, err := e.nodeVersion(ctx, e.path(DefaultNode))
	if err != nil {
		return fmt.Errorf("refused: can't tell which Node.js %s is: %w", DefaultNode, err)
	}
	if majorOf(current) == to && majors[to] && !majors[from] {
		e.say("%s is already Node.js v%s from NodeSource's node_%s.x: nothing to do", DefaultNode, current, to)
		return nil
	}
	if !majors[from] || len(majors) != 1 {
		return fmt.Errorf("refused: %s doesn't name deb.nodesource.com/node_%s.x alone", src, from)
	}
	if majorOf(current) != from {
		return fmt.Errorf("refused: %s is v%s, not Node.js %s", DefaultNode, current, from)
	}
	pkgVersion, err := e.nodejsVersion(ctx)
	if err != nil {
		return err
	}
	if pkgVersion == "" || !debVersionRe.MatchString(pkgVersion) {
		return fmt.Errorf("refused: the nodejs package isn't installed, so %s isn't NodeSource's", DefaultNode)
	}
	targets, err := e.targetsFor(ctx, DefaultNode, false)
	if err != nil {
		return err
	}

	dir, err := filebackup.NewDir(e.Root, defaultBackupRoot, e.Now())
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	en, err := filebackup.Save(e.Root, dir, "source", src, "apt")
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	m := defaultManifest{From: from, To: to, Nodejs: pkgVersion, Entries: []filebackup.Entry{en}}
	if err := filebackup.WriteManifest(dir, m); err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %s and the installed nodejs %s to %s", src, pkgVersion, e.host(dir))

	fail := func(cause error) error {
		if err := e.putDefaultBack(ctx, dir, m, targets); err != nil {
			return fmt.Errorf("%w; putting Node.js %s back failed too (backup in %s): %v", cause, from, e.host(dir), err)
		}
		return fmt.Errorf("%w; the source and nodejs %s were put back (backup in %s)", cause, pkgVersion, e.host(dir))
	}

	rewritten := strings.ReplaceAll(content, "deb.nodesource.com/node_"+from+".x", "deb.nodesource.com/node_"+to+".x")
	if err := writeSame(e.path(src), []byte(rewritten)); err != nil {
		return fail(err)
	}
	e.say("%s now names node_%s.x", src, to)
	if err := e.stream(ctx, "apt-get update", "/usr/bin/apt-get", "-q", "update"); err != nil {
		return fail(err)
	}
	if err := e.aptInstall(ctx, "nodejs"); err != nil {
		return fail(err)
	}
	now, err := e.nodeVersion(ctx, e.path(DefaultNode))
	if err != nil {
		return fail(err)
	}
	if majorOf(now) != to {
		return fail(fmt.Errorf("%s is v%s after the install, not Node.js %s", DefaultNode, now, to))
	}
	e.say("%s is Node.js v%s", DefaultNode, now)
	if err := e.restart(ctx, targets); err != nil {
		return fail(err)
	}
	if err := e.healthy(ctx, targets); err != nil {
		return fail(err)
	}
	e.say("The host's Node.js is now %s (v%s)", to, now)
	return nil
}

func (e *Env) aptInstall(ctx context.Context, spec string) error {
	return e.stream(ctx, "apt-get install "+spec, "/usr/bin/apt-get", "-q", "-y", "--allow-downgrades",
		"-o", "Dpkg::Options::=--force-confold", "install", spec)
}

// putDefaultBack restores the source, reinstalls the recorded nodejs (or
// the newest the old source has) and restarts what runs it.
func (e *Env) putDefaultBack(ctx context.Context, dir string, m defaultManifest, targets []target) error {
	if err := filebackup.Restore(e.Root, m.Entries, dir, nil); err != nil {
		return err
	}
	if err := e.stream(ctx, "apt-get update", "/usr/bin/apt-get", "-q", "update"); err != nil {
		return err
	}
	if err := e.aptInstall(ctx, "nodejs="+m.Nodejs); err != nil {
		e.say("nodejs %s isn't available any more; installing the newest Node.js %s instead", m.Nodejs, m.From)
		if err := e.aptInstall(ctx, "nodejs"); err != nil {
			return err
		}
	}
	if err := e.restart(ctx, targets); err != nil {
		return err
	}
	_ = filebackup.MarkRestored(dir, e.Now(), "the switch failed")
	return nil
}

// writeSame replaces a file's content, keeping its mode and owner.
func writeSame(p string, content []byte) error {
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	return filebackup.WriteLike(p, uint32(info.Mode().Perm()), uid, gid, content)
}
