package nginxops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

const (
	backupRoot  = "/var/backups/nginx-http2"
	stampLayout = "20060102T150405Z"
	// restoredMark is written into a backup once its lines are back (or
	// were never left changed), so it isn't restored twice.
	restoredMark = "restored"
	nginxBin     = "/usr/sbin/nginx"
	systemctl    = "/usr/bin/systemctl"
)

// Env holds what the operations need; tests replace all of it.
type Env struct {
	Runner runner.Runner
	Root   string
	Now    func() time.Time
	Out    io.Writer
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) say(format string, a ...any) { fmt.Fprintf(e.Out, format+"\n", a...) }

// Change is one line changed in one file.
type Change struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// fileEdit is one file's new content and how to write it back.
type fileEdit struct {
	Path string `json:"path"`
	Real string `json:"real"`
	Mode uint32 `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	old  []byte
	new  []byte
}

// Manifest is what a backup records: the lines it changed and the files.
type Manifest struct {
	Created string     `json:"created"`
	Changes []Change   `json:"changes"`
	Files   []fileEdit `json:"files"`
}

// Plan is what turning HTTP/2 off would change now, and the earlier
// changes that can still be put back. The nginx_http2 state tool reports it.
type Plan struct {
	Changes    []Change     `json:"changes"`
	FilesRead  int          `json:"files_read"`
	Skipped    []string     `json:"skipped_includes"`
	Restorable []Restorable `json:"restorable"`
}

// Restorable is one earlier change that turning HTTP/2 back on would undo.
type Restorable struct {
	Backup  string   `json:"backup"`
	Changes []Change `json:"changes"`
}

type span struct {
	start, end int
	with       string
}

// http2Edits finds what to change: an http2 flag on any listen in an http
// server block (except QUIC listens, which are HTTP/3), and http2 on in
// http{} or a server.
func http2Edits(c *config) map[*file][]span {
	out := map[*file][]span{}
	seen := map[*file]map[int]bool{}
	add := func(f *file, s span) {
		if seen[f] == nil {
			seen[f] = map[int]bool{}
		}
		if !seen[f][s.start] {
			seen[f][s.start] = true
			out[f] = append(out[f], s)
		}
	}
	for _, d := range c.directives {
		switch {
		case d.name.text == "listen" && d.in("http", "server"):
			quic := false
			for _, a := range d.args {
				quic = quic || (!a.quoted && a.text == "quic")
			}
			if quic {
				continue
			}
			for _, a := range d.args {
				if a.quoted || a.text != "http2" {
					continue
				}
				start := a.offset
				for start > 0 && (d.file.content[start-1] == ' ' || d.file.content[start-1] == '\t') {
					start--
				}
				add(d.file, span{start: start, end: a.offset + len("http2")})
			}
		case d.name.text == "http2" && (d.in("http") || d.in("http", "server")) && len(d.args) == 1 && d.args[0].text == "on":
			a := d.args[0]
			end := a.offset + len("on")
			if a.quoted {
				end += 2
			}
			add(d.file, span{start: a.offset, end: end, with: "off"})
		}
	}
	return out
}

// plan works out every file's new content and the lines that change.
func plan(c *config) ([]fileEdit, []Change, error) {
	edits := http2Edits(c)
	var files []fileEdit
	var changes []Change
	for _, f := range c.files {
		spans := edits[f]
		if len(spans) == 0 {
			continue
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
		content := append([]byte(nil), f.content...)
		for _, s := range spans {
			content = append(content[:s.start], append([]byte(s.with), content[s.end:]...)...)
		}
		fe, err := statEdit(f)
		if err != nil {
			return nil, nil, err
		}
		fe.new = content
		files = append(files, fe)
		changes = append(changes, lineChanges(f.path, f.content, content)...)
	}
	return files, changes, nil
}

func statEdit(f *file) (fileEdit, error) {
	info, err := os.Stat(f.real)
	if err != nil {
		return fileEdit{}, err
	}
	fe := fileEdit{Path: f.path, Real: f.real, Mode: uint32(info.Mode().Perm()), UID: -1, GID: -1, old: f.content}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		fe.UID, fe.GID = int(st.Uid), int(st.Gid)
	}
	return fe, nil
}

// lineChanges lists the lines that differ. The edits never add or remove a
// newline, so line numbers match.
func lineChanges(path string, before, after []byte) []Change {
	a, b := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	var out []Change
	for i := range a {
		if i < len(b) && a[i] != b[i] {
			out = append(out, Change{File: path, Line: i + 1, Before: a[i], After: b[i]})
		}
	}
	return out
}

// HTTP2Plan reports what HTTP2Off would change, changing nothing.
func (e *Env) HTTP2Plan() (*Plan, error) {
	c, err := load(e.Root)
	if err != nil {
		return nil, err
	}
	_, changes, err := plan(c)
	if err != nil {
		return nil, err
	}
	backups, err := e.unrestored()
	if err != nil {
		return nil, err
	}
	p := &Plan{Changes: changes, FilesRead: len(c.files), Skipped: c.skipped, Restorable: []Restorable{}}
	if p.Changes == nil {
		p.Changes = []Change{}
	}
	if p.Skipped == nil {
		p.Skipped = []string{}
	}
	for _, b := range backups {
		p.Restorable = append(p.Restorable, Restorable{Backup: filepath.Base(b.dir), Changes: b.m.Changes})
	}
	return p, nil
}

// HTTP2Off turns HTTP/2 off everywhere nginx reads config, backing up each
// file it changes first. Unless nginx -t and the reload pass, every file is
// put back and nginx reloaded as it was.
func (e *Env) HTTP2Off(ctx context.Context) error {
	if _, err := os.Stat(e.path(nginxBin)); err != nil {
		return fmt.Errorf("refused: no nginx at %s", nginxBin)
	}
	c, err := load(e.Root)
	if err != nil {
		return err
	}
	files, changes, err := plan(c)
	if err != nil {
		return err
	}
	for _, s := range c.skipped {
		e.say("Not read: include %s", s)
	}
	if len(changes) == 0 {
		e.say("HTTP/2 is already off in the %d files nginx reads: nothing to change", len(c.files))
		return nil
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fmt.Errorf("refused, nothing was changed: nginx's configuration already fails its test, so fix that first: %w", err)
	}
	m := Manifest{Created: e.Now().UTC().Format(time.RFC3339), Changes: changes, Files: files}
	dir, err := e.backup(m)
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %d file(s) to %s", len(files), dir)
	printDiff(e.Out, changes)
	fail := func(cause error) error {
		perr := e.putBack(ctx, files)
		// Nothing is left changed, so there's nothing to restore later.
		_ = os.WriteFile(filepath.Join(dir, restoredMark), []byte(e.Now().UTC().Format(time.RFC3339)+" put back after a failure\n"), 0o600)
		if perr != nil {
			return fmt.Errorf("%w; putting the files back failed too (backup in %s): %v", cause, dir, perr)
		}
		return fmt.Errorf("%w; every file was put back (backup in %s)", cause, dir)
	}
	for _, f := range files {
		if err := writeLike(f, f.new); err != nil {
			return fail(fmt.Errorf("writing %s: %w", f.Path, err))
		}
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fail(err)
	}
	if err := e.check(ctx, "reloading nginx", systemctl, "reload", "nginx"); err != nil {
		return fail(err)
	}
	e.say("HTTP/2 is off: %d line(s) in %d file(s) changed, nginx -t passed and nginx reloaded", len(changes), len(files))
	return nil
}

// HTTP2Restore puts back exactly the lines earlier HTTP2Off runs changed,
// newest first, then runs nginx -t and reloads. It refuses, changing
// nothing, if any of those lines has changed since.
func (e *Env) HTTP2Restore(ctx context.Context) error {
	backups, err := e.unrestored()
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		e.say("No HTTP/2 change to put back: nothing to do")
		return nil
	}
	// Each file's current content, and its content with the lines back.
	current := map[string]*fileEdit{}
	var order []string
	var problems, changes []string
	for _, b := range backups {
		for _, f := range b.m.Files {
			if _, ok := current[f.Real]; ok {
				continue
			}
			content, err := os.ReadFile(f.Real)
			if err != nil {
				return fmt.Errorf("reading %s: %w", f.Path, err)
			}
			fe := f
			fe.old, fe.new = content, content
			current[f.Real] = &fe
			order = append(order, f.Real)
		}
		for _, ch := range b.m.Changes {
			var fe *fileEdit
			for _, f := range b.m.Files {
				if f.Path == ch.File {
					fe = current[f.Real]
				}
			}
			if fe == nil {
				problems = append(problems, fmt.Sprintf("%s:%d: the backup doesn't list the file", ch.File, ch.Line))
				continue
			}
			lines := strings.Split(string(fe.new), "\n")
			if ch.Line > len(lines) || lines[ch.Line-1] != ch.After {
				problems = append(problems, fmt.Sprintf("%s:%d has changed since HTTP/2 was turned off (expected %q)", ch.File, ch.Line, strings.TrimSpace(ch.After)))
				continue
			}
			lines[ch.Line-1] = ch.Before
			fe.new = []byte(strings.Join(lines, "\n"))
			changes = append(changes, fmt.Sprintf("%s:%d", ch.File, ch.Line))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("refused, nothing was changed: %s", strings.Join(problems, "; "))
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fmt.Errorf("refused, nothing was changed: nginx's configuration already fails its test, so fix that first: %w", err)
	}
	var files []fileEdit
	for _, real := range order {
		files = append(files, *current[real])
	}
	fail := func(cause error) error {
		if err := e.putBack(ctx, files); err != nil {
			return fmt.Errorf("%w; putting the files back failed too: %v", cause, err)
		}
		return fmt.Errorf("%w; every file was put back as it was", cause)
	}
	for _, f := range files {
		if err := writeLike(f, f.new); err != nil {
			return fail(fmt.Errorf("writing %s: %w", f.Path, err))
		}
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		return fail(err)
	}
	if err := e.check(ctx, "reloading nginx", systemctl, "reload", "nginx"); err != nil {
		return fail(err)
	}
	for _, b := range backups {
		if err := os.WriteFile(filepath.Join(b.dir, restoredMark), []byte(e.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			return fmt.Errorf("the lines are back, but marking %s restored failed: %w", b.dir, err)
		}
		printDiff(e.Out, reversed(b.m.Changes))
	}
	e.say("HTTP/2 is back as it was: %d line(s) restored, nginx -t passed and nginx reloaded", len(changes))
	return nil
}

func reversed(changes []Change) []Change {
	out := make([]Change, len(changes))
	for i, c := range changes {
		out[i] = Change{File: c.File, Line: c.Line, Before: c.After, After: c.Before}
	}
	return out
}

// printDiff prints the changes as a unified diff, one hunk per line.
func printDiff(w io.Writer, changes []Change) {
	last := ""
	for _, c := range changes {
		if c.File != last {
			fmt.Fprintf(w, "--- %s\n+++ %s\n", c.File, c.File)
			last = c.File
		}
		fmt.Fprintf(w, "@@ -%d +%d @@\n-%s\n+%s\n", c.Line, c.Line, c.Before, c.After)
	}
}

type backup struct {
	dir string
	m   Manifest
}

// unrestored lists the backups whose lines haven't been put back, newest
// first.
func (e *Env) unrestored() ([]backup, error) {
	root := e.path(backupRoot)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []backup
	for _, ent := range entries {
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
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("reading backup %s: %w", ent.Name(), err)
		}
		for i := range m.Files {
			m.Files[i].Real = e.path(strings.TrimPrefix(m.Files[i].Real, e.Root))
		}
		out = append(out, backup{dir: dir, m: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir > out[j].dir })
	return out, nil
}

func (e *Env) backup(m Manifest) (string, error) {
	root := e.path(backupRoot)
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
	for i, f := range m.Files {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)), f.old, 0o600); err != nil {
			return "", err
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// putBack writes every file's old content back and reloads nginx.
func (e *Env) putBack(ctx context.Context, files []fileEdit) error {
	var errs []error
	for _, f := range files {
		if err := writeLike(f, f.old); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
		}
	}
	if err := e.check(ctx, "nginx -t", nginxBin, "-t"); err != nil {
		errs = append(errs, err)
	} else if err := e.check(ctx, "reloading nginx", systemctl, "reload", "nginx"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// writeLike replaces the file's content by renaming a temporary file in the
// same directory over it, keeping its mode and owner.
func writeLike(f fileEdit, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.Real), ".bifrost-nginx-*")
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
	if err := tmp.Chmod(os.FileMode(f.Mode)); err != nil {
		return cleanup(err)
	}
	if f.UID >= 0 {
		if err := tmp.Chown(f.UID, f.GID); err != nil {
			return cleanup(err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, f.Real); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (e *Env) check(ctx context.Context, what string, argv ...string) error {
	var out, errOut strings.Builder
	code, err := e.Runner.Run(ctx, runner.Command{Argv: argv, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("%s failed with status %d:\n%s", what, code, lastLines(errOut.String()+out.String(), 20))
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
