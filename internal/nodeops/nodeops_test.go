package nodeops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// fakeHost is an apt host under a temporary root, with a fake runner and
// a fake nodejs.org.
type fakeHost struct {
	t    *testing.T
	root string
	out  bytes.Buffer
	env  *Env

	mu    sync.Mutex
	calls []string
	// versions is what each node binary's --version prints, by host path.
	versions map[string]string
	gpgvCode int
	// status is what `supervisorctl status NAME:*` prints, in turn; the
	// last answer repeats.
	status map[string][]string
	// units is each unit's `systemctl show` answer, in turn.
	units map[string][]string
	// fail makes commands starting with a prefix exit 1.
	fail []string
	// onCall runs for every command.
	onCall func(argv []string)

	dist *fakeDist
}

type fakeDist struct {
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func (d *fakeDist) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hits[r.URL.Path]++
	b, ok := d.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

func newHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, root: t.TempDir(), versions: map[string]string{}, status: map[string][]string{}, units: map[string][]string{}}
	h.write("etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\n", 0o644)
	h.dist = &fakeDist{files: map[string][]byte{}, hits: map[string]int{}}
	srv := httptest.NewServer(h.dist)
	t.Cleanup(srv.Close)
	h.env = &Env{
		Runner: runnerFunc(h.run), Root: h.root, Out: &h.out, DistURL: srv.URL, Client: srv.Client(), Arch: "amd64",
		Now:   func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) },
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	return h
}

type runnerFunc func(ctx context.Context, c runner.Command) (int, error)

func (f runnerFunc) Run(ctx context.Context, c runner.Command) (int, error) { return f(ctx, c) }

func (h *fakeHost) run(_ context.Context, c runner.Command) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	argv := make([]string, len(c.Argv))
	for i, a := range c.Argv {
		argv[i] = strings.ReplaceAll(a, h.root, "")
	}
	key := strings.Join(argv, " ")
	h.calls = append(h.calls, key)
	if h.onCall != nil {
		h.onCall(argv)
	}
	for _, p := range h.fail {
		if strings.HasPrefix(key, p) {
			return 1, nil
		}
	}
	write := func(s string) {
		if c.Stdout != nil {
			fmt.Fprint(c.Stdout, s)
		}
	}
	switch {
	case len(argv) == 2 && argv[1] == "--version":
		v, ok := h.versions[argv[0]]
		if !ok {
			return 127, nil
		}
		write("v" + v + "\n")
	case argv[0] == "/usr/bin/gpgv":
		if h.gpgvCode != 0 {
			fmt.Fprint(c.Stderr, "gpgv: Can't check signature: No public key\n")
		}
		return h.gpgvCode, nil
	case len(argv) == 3 && argv[0] == "/usr/bin/supervisorctl" && argv[1] == "status":
		name := strings.TrimSuffix(argv[2], ":*")
		q := h.status[name]
		if len(q) == 0 {
			return 4, nil
		}
		write(q[0])
		if len(q) > 1 {
			h.status[name] = q[1:]
		}
	case len(argv) >= 3 && argv[0] == "/usr/bin/systemctl" && argv[1] == "show":
		q := h.units[argv[2]]
		if len(q) == 0 {
			write("ActiveState=inactive\nNRestarts=0\n")
			return 0, nil
		}
		write(q[0])
		if len(q) > 1 {
			h.units[argv[2]] = q[1:]
		}
	case argv[0] == "/usr/bin/dpkg-query":
		if v := h.versions["dpkg:nodejs"]; v != "" {
			write("ii \t" + v + "\n")
			return 0, nil
		}
		return 1, nil
	}
	return 0, nil
}

func (h *fakeHost) called(prefix string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (h *fakeHost) write(rel, content string, mode os.FileMode) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) read(rel string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.root, rel))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *fakeHost) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(h.root, rel))
	return err == nil
}

// installTree puts a side install of version at /opt/node/NN.
func (h *fakeHost) installTree(version string) {
	major := majorOf(version)
	dir := "opt/node/" + major
	h.write(dir+"/bin/node", "#!fake\n", 0o755)
	h.write(dir+"/include/node/node_version.h", header(version), 0o644)
	h.versions["/"+dir+"/bin/node"] = version
}

func header(version string) string {
	p := strings.Split(version, ".")
	return fmt.Sprintf("#ifndef SRC_NODE_VERSION_H_\n#define NODE_MAJOR_VERSION %s\n#define NODE_MINOR_VERSION %s\n#define NODE_PATCH_VERSION %s\n", p[0], p[1], p[2])
}

type entry struct {
	name string
	typ  byte
	body string
	link string
	mode int64
}

func validTree(version string) []entry {
	top := "node-v" + version + "-linux-x64/"
	return []entry{
		{name: top, typ: tar.TypeDir, mode: 0o775},
		{name: top + "bin/", typ: tar.TypeDir, mode: 0o775},
		{name: top + "bin/node", typ: tar.TypeReg, body: "#!fake\n", mode: 0o777},
		{name: top + "include/node/node_version.h", typ: tar.TypeReg, body: header(version), mode: 0o664},
		{name: top + "lib/node_modules/npm/bin/npm-cli.js", typ: tar.TypeReg, body: "// npm\n", mode: 0o755},
		{name: top + "bin/npm", typ: tar.TypeSymlink, link: "../lib/node_modules/npm/bin/npm-cli.js"},
	}
}

func tarball(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// publish serves version (and older releases) on the fake nodejs.org with
// the tarball built from entries, and a SHASUMS256.txt with sum (the
// tarball's own when empty).
func (h *fakeHost) publish(version string, entries []entry, sum string) {
	tb := tarball(h.t, entries)
	if sum == "" {
		s := sha256.Sum256(tb)
		sum = hex.EncodeToString(s[:])
	}
	index, _ := json.Marshal([]map[string]any{
		{"version": "v23.0.0"}, {"version": "v" + version}, {"version": "v22.11.0"}, {"version": "v22.9.0"},
		{"version": "v22.99.0-rc.1"}, {"version": "v20.18.1"},
	})
	name := "node-v" + version + "-linux-x64.tar.gz"
	h.dist.files["/index.json"] = index
	h.dist.files["/v"+version+"/SHASUMS256.txt"] = []byte(fmt.Sprintf("%s  node-v%s-linux-arm64.tar.gz\n%s  %s\n", strings.Repeat("0", 64), version, sum, name))
	h.dist.files["/v"+version+"/SHASUMS256.txt.sig"] = []byte("signature")
	h.dist.files["/v"+version+"/"+name] = tb
	// What the unpacked node prints.
	h.versions["/opt/node/."+majorOf(version)+".new/bin/node"] = version
}

func leftovers(t *testing.T, root string) []string {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(root, "opt/node"))
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestInstall(t *testing.T) {
	h := newHost(t)
	h.publish("22.12.0", validTree("22.12.0"), "")
	if err := h.env.Install(context.Background(), "22"); err != nil {
		t.Fatalf("install: %v\n%s", err, h.out.String())
	}
	if got := h.read("opt/node/22/include/node/node_version.h"); !strings.Contains(got, "NODE_MINOR_VERSION 12") {
		t.Fatalf("header = %q", got)
	}
	info, err := os.Stat(filepath.Join(h.root, "opt/node/22/bin/node"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("bin/node mode = %v, %v", info.Mode(), err)
	}
	if info, _ := os.Stat(filepath.Join(h.root, "opt/node/22/include/node/node_version.h")); info.Mode().Perm() != 0o644 {
		t.Fatalf("header mode = %v", info.Mode())
	}
	if info, _ := os.Stat(filepath.Join(h.root, "opt/node/22/bin")); info.Mode().Perm() != 0o755 {
		t.Fatalf("bin mode = %v", info.Mode())
	}
	if link, err := os.Readlink(filepath.Join(h.root, "opt/node/22/bin/npm")); err != nil || link != "../lib/node_modules/npm/bin/npm-cli.js" {
		t.Fatalf("npm link = %q, %v", link, err)
	}
	if l := leftovers(t, h.root); len(l) != 0 {
		t.Fatalf("left behind: %v", l)
	}
	if !h.called("/usr/bin/gpgv --homedir /opt/node/.22.download-") || !h.called("/opt/node/.22.new/bin/node --version") {
		t.Fatalf("calls = %v", h.calls)
	}
	if h.dist.hits["/v22.12.0/node-v22.12.0-linux-x64.tar.gz"] != 1 {
		t.Fatalf("hits = %v", h.dist.hits)
	}

	err = h.env.Install(context.Background(), "22")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second install: %v", err)
	}
}

func TestInstallRefusals(t *testing.T) {
	top := "node-v22.12.0-linux-x64/"
	withEntry := func(e entry) []entry { return append(validTree("22.12.0"), e) }
	cases := []struct {
		name    string
		entries []entry
		sum     string
		gpgv    int
		arch    string
		major   string
		want    string
	}{
		{name: "bad hash", entries: validTree("22.12.0"), sum: strings.Repeat("ab", 32), want: "but the signed SHASUMS256.txt says"},
		{name: "bad signature", entries: validTree("22.12.0"), gpgv: 2, want: "isn't signed by a Node.js release key this agent trusts"},
		{name: "unsupported arch", entries: validTree("22.12.0"), arch: "riscv64", want: "amd64 and arm64 only"},
		{name: "no release", entries: validTree("22.12.0"), major: "19", want: "has no release of Node.js 19"},
		{name: "dot dot", entries: withEntry(entry{name: top + "../evil", typ: tar.TypeReg, body: "x", mode: 0o644}), want: "leaves the tree"},
		{name: "absolute", entries: withEntry(entry{name: "/etc/cron.d/evil", typ: tar.TypeReg, body: "x", mode: 0o644}), want: "absolute"},
		{name: "other top", entries: withEntry(entry{name: "elsewhere/x", typ: tar.TypeReg, body: "x", mode: 0o644}), want: "isn't under"},
		{name: "absolute symlink", entries: withEntry(entry{name: top + "bin/evil", typ: tar.TypeSymlink, link: "/etc/shadow"}), want: "isn't relative"},
		{name: "escaping symlink", entries: withEntry(entry{name: top + "bin/evil", typ: tar.TypeSymlink, link: "../../../etc"}), want: "points outside the tree"},
		{name: "through symlink", entries: append(withEntry(entry{name: top + "lib/x", typ: tar.TypeSymlink, link: "."}),
			entry{name: top + "lib/x/y", typ: tar.TypeReg, body: "x", mode: 0o644}), want: "below the symlink"},
		{name: "hard link", entries: withEntry(entry{name: top + "bin/hard", typ: tar.TypeLink, link: top + "bin/node"}), want: "only files, directories and symlinks"},
		{name: "device", entries: withEntry(entry{name: top + "dev", typ: tar.TypeChar}), want: "only files, directories and symlinks"},
		{name: "no header", entries: validTree("22.12.0")[:3], want: "no include/node/node_version.h"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			h.publish("22.12.0", c.entries, c.sum)
			h.gpgvCode = c.gpgv
			if c.arch != "" {
				h.env.Arch = c.arch
			}
			major := "22"
			if c.major != "" {
				major = c.major
			}
			err := h.env.Install(context.Background(), major)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if h.exists("opt/node/22") {
				t.Fatal("/opt/node/22 was installed")
			}
			if l := leftovers(t, h.root); len(l) != 0 {
				t.Fatalf("left behind: %v", l)
			}
			if h.exists("etc/cron.d/evil") || h.exists("opt/node/evil") {
				t.Fatal("wrote outside the tree")
			}
		})
	}
}

func TestBadMajor(t *testing.T) {
	h := newHost(t)
	for _, m := range []string{"", "2", "222", "-1", "../", "09"} {
		if err := h.env.Install(context.Background(), m); err == nil || !strings.Contains(err.Error(), "bad Node.js major") {
			t.Errorf("Install(%q) = %v", m, err)
		}
	}
}

const appProgram = `[program:app-worker]
command=/opt/node/22/bin/node /home/acme/app/worker.js
directory=/home/acme/app
autostart=true
`

func TestUpdate(t *testing.T) {
	t.Run("already newest", func(t *testing.T) {
		h := newHost(t)
		h.installTree("22.12.0")
		h.publish("22.12.0", validTree("22.12.0"), "")
		if err := h.env.Update(context.Background(), "22"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(h.out.String(), "nothing to do") || h.dist.hits["/v22.12.0/SHASUMS256.txt"] != 0 {
			t.Fatalf("out = %s, hits = %v", h.out.String(), h.dist.hits)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		h := newHost(t)
		if err := h.env.Update(context.Background(), "22"); err == nil || !strings.Contains(err.Error(), "isn't installed") {
			t.Fatal(err)
		}
	})
	t.Run("healthy", func(t *testing.T) {
		h := newHost(t)
		h.installTree("22.11.0")
		h.publish("22.12.0", validTree("22.12.0"), "")
		h.write("etc/supervisor/conf.d/app.conf", appProgram, 0o644)
		h.write("etc/systemd/system/api.service", "[Service]\nExecStart=/usr/bin/env node /home/acme/api/index.js\nEnvironment=PATH=/opt/node/22/bin:/usr/bin\n", 0o644)
		h.write("etc/systemd/system/other.service", "[Service]\nExecStart=/opt/node/20/bin/node /srv/other.js\n", 0o644)
		h.status["app-worker"] = []string{"app-worker   RUNNING   pid 10, uptime 1:00:00\n"}
		h.units["api.service"] = []string{"ActiveState=active\nNRestarts=0\n"}
		if err := h.env.Update(context.Background(), "22"); err != nil {
			t.Fatalf("update: %v\n%s", err, h.out.String())
		}
		if v, _ := h.env.headerVersion(filepath.Join(h.root, "opt/node/22")); v != "22.12.0" {
			t.Fatalf("version = %s", v)
		}
		if v, _ := h.env.headerVersion(filepath.Join(h.root, "opt/node/.22.previous")); v != "22.11.0" {
			t.Fatalf("previous = %s", v)
		}
		if !h.called("/usr/bin/supervisorctl restart app-worker:*") || !h.called("/usr/bin/systemctl restart api.service") || h.called("/usr/bin/systemctl restart other.service") {
			t.Fatalf("calls = %v", h.calls)
		}
	})
	t.Run("swaps back on failed health", func(t *testing.T) {
		h := newHost(t)
		h.installTree("22.11.0")
		h.write("opt/node/.22.previous/stale", "", 0o644)
		h.publish("22.12.0", validTree("22.12.0"), "")
		h.write("etc/supervisor/conf.d/app.conf", appProgram, 0o644)
		h.write("etc/systemd/system/api.service", "[Service]\nExecStart=/opt/node/22/bin/node /home/acme/api/index.js\n", 0o644)
		h.status["app-worker"] = []string{"app-worker   RUNNING   pid 10\n"}
		// Running before, then crash-looping after the restart.
		h.units["api.service"] = []string{"ActiveState=active\nNRestarts=0\n", "ActiveState=active\nNRestarts=0\n", "ActiveState=active\nNRestarts=3\n"}
		err := h.env.Update(context.Background(), "22")
		if err == nil || !strings.Contains(err.Error(), "api.service restarted 3 time(s)") || !strings.Contains(err.Error(), "v22.11.0 was put back") {
			t.Fatalf("err = %v", err)
		}
		if v, _ := h.env.headerVersion(filepath.Join(h.root, "opt/node/22")); v != "22.11.0" {
			t.Fatalf("version = %s", v)
		}
		if l := leftovers(t, h.root); len(l) != 0 {
			t.Fatalf("left behind: %v", l)
		}
		n := 0
		for _, c := range h.calls {
			if c == "/usr/bin/systemctl restart api.service" {
				n++
			}
		}
		if n != 2 {
			t.Fatalf("api.service restarted %d times, want 2 (update and swap back)", n)
		}
	})
}

func TestRemoveRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *fakeHost)
		want  string
	}{
		{"systemd unit", func(h *fakeHost) {
			h.write("etc/systemd/system/app.service", "[Service]\nExecStart=/opt/node/20/bin/node /srv/app.js\n", 0o644)
		}, "/etc/systemd/system/app.service:2"},
		{"drop-in", func(h *fakeHost) {
			h.write("etc/systemd/system/app.service.d/path.conf", "[Service]\nEnvironment=PATH=/opt/node/20/bin:/usr/bin\n", 0o644)
		}, "/etc/systemd/system/app.service.d/path.conf:2"},
		{"supervisor", func(h *fakeHost) {
			h.write("etc/supervisor/conf.d/app.conf", "[program:app]\ncommand=/opt/node/20/bin/node x.js\n", 0o644)
		}, "/etc/supervisor/conf.d/app.conf:2"},
		{"crontab", func(h *fakeHost) {
			h.write("var/spool/cron/crontabs/acme", "* * * * * /opt/node/20/bin/node /home/acme/x.js\n", 0o600)
		}, "/var/spool/cron/crontabs/acme:1"},
		{"process", func(h *fakeHost) {
			os.MkdirAll(filepath.Join(h.root, "proc/4242"), 0o755)
			os.Symlink("/opt/node/20/bin/node", filepath.Join(h.root, "proc/4242/exe"))
		}, "PID 4242 runs /opt/node/20/bin/node"},
		{"pm2", func(h *fakeHost) {
			h.write("home/acme/.pm2/dump.pm2", `[{"exec_interpreter":"/opt/node/20/bin/node","pm_cwd":"/home/acme/app"}]`, 0o644)
		}, "/home/acme/.pm2/dump.pm2:1"},
		{"not installed", func(h *fakeHost) { os.RemoveAll(filepath.Join(h.root, "opt/node/20")) }, "isn't installed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			h.installTree("20.18.1")
			// Neither of these counts.
			h.write("etc/systemd/system/old.service", "[Service]\n# ExecStart=/opt/node/20/bin/node x\nExecStart=/opt/node/200/bin/node y\n", 0o644)
			os.MkdirAll(filepath.Join(h.root, "proc/1"), 0o755)
			os.Symlink("/usr/lib/systemd/systemd", filepath.Join(h.root, "proc/1/exe"))
			c.setup(h)
			err := h.env.Remove(context.Background(), "20")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if c.name != "not installed" && !h.exists("opt/node/20/bin/node") {
				t.Fatal("removed anyway")
			}
		})
	}
}

func TestRemoveAndRestore(t *testing.T) {
	h := newHost(t)
	h.installTree("20.18.1")
	ctx := context.Background()
	if err := h.env.Restore(ctx, "20"); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("restore over an install: %v", err)
	}
	if err := h.env.Remove(ctx, "20"); err != nil {
		t.Fatal(err)
	}
	backup := "var/backups/node-remove/20-v20.18.1-20261120T120000Z"
	if h.exists("opt/node/20") || !h.exists(backup+"/bin/node") {
		t.Fatal("not moved to the backup")
	}
	// An older backup is ignored.
	h.write("var/backups/node-remove/20-v20.17.0-20261001T000000Z/bin/node", "old", 0o755)
	if err := h.env.Restore(ctx, "20"); err != nil {
		t.Fatal(err)
	}
	if v, _ := h.env.headerVersion(filepath.Join(h.root, "opt/node/20")); v != "20.18.1" || h.exists(backup) {
		t.Fatalf("restored %q", v)
	}
	if err := h.env.Restore(ctx, "18"); err == nil || !strings.Contains(err.Error(), "no backup") {
		t.Fatalf("restore without a backup: %v", err)
	}
}

const siteRoot = "/home/acme/app"

// switchHost has one site on /opt/node/20 and a neighbour that must not
// move.
func switchHost(t *testing.T) *fakeHost {
	h := newHost(t)
	h.installTree("20.18.1")
	h.installTree("22.12.0")
	h.write("home/acme/app/server.js", "", 0o644)
	h.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nacme:x:"+fmt.Sprint(os.Getuid())+":1000::/home/acme:/bin/bash\n", 0o644)
	h.write("etc/supervisor/conf.d/sites.conf", `[program:app-web]
command=/opt/node/20/bin/node server.js
directory=/home/acme/app
environment=PATH="/opt/node/20/bin:/usr/bin:/bin",NODE_ENV="production"

[program:app.old-web]
command=/opt/node/20/bin/node /home/acme/app.old/server.js
environment=PATH="/opt/node/20/bin:/usr/bin"
`, 0o644)
	h.write("etc/systemd/system/app-queue.service", "[Service]\nWorkingDirectory=/home/acme/app\nExecStart=/opt/node/20/bin/node queue.js\n", 0o644)
	h.write("etc/systemd/system/app-queue.service.d/env.conf", "[Service]\nEnvironment=PATH=/opt/node/20/bin:/usr/bin\n", 0o644)
	h.write("var/spool/cron/crontabs/acme", "# m h dom mon dow command\n* * * * * cd /home/acme/app && /opt/node/20/bin/node cron.js\n0 * * * * /opt/node/20/bin/node /home/acme/other/cron.js\n", 0o600)
	h.status["app-web"] = []string{"app-web   RUNNING   pid 10\n"}
	h.units["app-queue.service"] = []string{"ActiveState=active\nNRestarts=1\n"}
	return h
}

func TestSwitchSite(t *testing.T) {
	h := switchHost(t)
	ctx := context.Background()
	if err := h.env.SwitchSite(ctx, siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node"); err != nil {
		t.Fatalf("switch: %v\n%s", err, h.out.String())
	}
	sup := h.read("etc/supervisor/conf.d/sites.conf")
	if !strings.Contains(sup, "command=/opt/node/22/bin/node server.js\ndirectory=/home/acme/app\nenvironment=PATH=\"/opt/node/22/bin:/usr/bin:/bin\"") {
		t.Fatalf("supervisor = %s", sup)
	}
	if !strings.Contains(sup, "command=/opt/node/20/bin/node /home/acme/app.old/server.js\nenvironment=PATH=\"/opt/node/20/bin:/usr/bin\"") {
		t.Fatalf("the neighbour moved: %s", sup)
	}
	if got := h.read("etc/systemd/system/app-queue.service"); !strings.Contains(got, "ExecStart=/opt/node/22/bin/node queue.js") {
		t.Fatalf("unit = %s", got)
	}
	if got := h.read("etc/systemd/system/app-queue.service.d/env.conf"); !strings.Contains(got, "PATH=/opt/node/22/bin:/usr/bin") {
		t.Fatalf("drop-in = %s", got)
	}
	cron := h.read("var/spool/cron/crontabs/acme")
	if !strings.Contains(cron, "cd /home/acme/app && /opt/node/22/bin/node cron.js") || !strings.Contains(cron, "/opt/node/20/bin/node /home/acme/other/cron.js") {
		t.Fatalf("cron = %s", cron)
	}
	if info, _ := os.Stat(filepath.Join(h.root, "var/spool/cron/crontabs/acme")); info.Mode().Perm() != 0o600 {
		t.Fatalf("crontab mode = %v", info.Mode())
	}
	for _, want := range []string{"/usr/bin/supervisorctl reread", "/usr/bin/supervisorctl update", "/usr/bin/systemctl daemon-reload", "/usr/bin/systemctl restart app-queue.service"} {
		if !h.called(want) {
			t.Errorf("no %q in %v", want, h.calls)
		}
	}
	if h.called("/usr/sbin/runuser") {
		t.Error("rebuilt without native modules")
	}
	backups, _ := filepath.Glob(filepath.Join(h.root, "var/backups/node-switch/*/manifest.json"))
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}

	// Again: already moved.
	h.out.Reset()
	if err := h.env.SwitchSite(ctx, siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node"); err != nil || !strings.Contains(h.out.String(), "already moved") {
		t.Fatalf("second switch: %v\n%s", err, h.out.String())
	}
}

func TestSwitchSiteRollsBack(t *testing.T) {
	h := switchHost(t)
	h.write("home/acme/app/node_modules/bcrypt/build/Release/bcrypt_lib.node", "elf", 0o755)
	// Running before, then FATAL after the update.
	h.status["app-web"] = []string{"app-web   RUNNING   pid 10\n", "app-web   FATAL     Exited too quickly\n"}
	before := map[string]string{}
	files := []string{"etc/supervisor/conf.d/sites.conf", "etc/systemd/system/app-queue.service", "etc/systemd/system/app-queue.service.d/env.conf", "var/spool/cron/crontabs/acme"}
	for _, f := range files {
		before[f] = h.read(f)
	}
	err := h.env.SwitchSite(context.Background(), siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node")
	if err == nil || !strings.Contains(err.Error(), "supervisor program app-web isn't RUNNING") || !strings.Contains(err.Error(), "every file was put back") {
		t.Fatalf("err = %v\n%s", err, h.out.String())
	}
	for _, f := range files {
		if got := h.read(f); got != before[f] {
			t.Errorf("%s = %q, want %q", f, got, before[f])
		}
	}
	rebuild := fmt.Sprintf("/usr/sbin/runuser -u acme -- /usr/bin/env -C %s HOME=/home/acme PATH=/opt/node/22/bin:/usr/bin:/bin /opt/node/22/bin/npm rebuild", siteRoot)
	if !h.called(rebuild) {
		t.Fatalf("no rebuild in %v", h.calls)
	}
	if !h.called("/usr/bin/cp -a -- /home/acme/app/node_modules /var/backups/node-switch/") || !h.called("/usr/bin/cp -a -- /var/backups/node-switch/20261120T120000Z/node_modules /home/acme/app/node_modules") {
		t.Fatalf("node_modules not backed up and put back: %v", h.calls)
	}
	// The rollback (swapped) then finds nothing to do.
	h.out.Reset()
	if err := h.env.SwitchSite(context.Background(), siteRoot, "/opt/node/22/bin/node", "/opt/node/20/bin/node"); err != nil || !strings.Contains(h.out.String(), "already moved") {
		t.Fatalf("rollback: %v\n%s", err, h.out.String())
	}
}

func TestSwitchSiteFromDefault(t *testing.T) {
	h := newHost(t)
	h.installTree("22.12.0")
	h.write("usr/bin/node", "#!fake\n", 0o755)
	h.write("home/acme/app/index.js", "", 0o644)
	h.write("etc/systemd/system/app.service", "[Service]\nWorkingDirectory=/home/acme/app\nExecStart=/usr/bin/node index.js\nEnvironment=PATH=/usr/bin:/bin\n", 0o644)
	h.write("etc/cron.d/app", "* * * * * acme cd /home/acme/app && node tick.js >/dev/null 2>&1\n", 0o644)
	h.units["app.service"] = []string{"ActiveState=active\nNRestarts=0\n"}
	ctx := context.Background()
	if err := h.env.SwitchSite(ctx, siteRoot, "/usr/bin/node", "/opt/node/22/bin/node"); err != nil {
		t.Fatalf("switch: %v\n%s", err, h.out.String())
	}
	unit := h.read("etc/systemd/system/app.service")
	if !strings.Contains(unit, "ExecStart=/opt/node/22/bin/node index.js") || !strings.Contains(unit, "Environment=PATH=/opt/node/22/bin:/usr/bin:/bin") {
		t.Fatalf("unit = %s", unit)
	}
	if got := h.read("etc/cron.d/app"); !strings.Contains(got, "&& /opt/node/22/bin/node tick.js") {
		t.Fatalf("cron = %s", got)
	}
	// And back, as the rollback would.
	if err := h.env.SwitchSite(ctx, siteRoot, "/opt/node/22/bin/node", "/usr/bin/node"); err != nil {
		t.Fatalf("switch back: %v\n%s", err, h.out.String())
	}
	if got := h.read("etc/systemd/system/app.service"); !strings.Contains(got, "ExecStart=/usr/bin/node index.js") || !strings.Contains(got, "Environment=PATH=/usr/bin:/bin\n") {
		t.Fatalf("unit after switching back = %s", got)
	}
}

func TestSwitchSiteRefusals(t *testing.T) {
	cases := []struct {
		name           string
		root, from, to string
		setup          func(h *fakeHost)
		want           string
	}{
		{"root slash", "/", "/opt/node/20/bin/node", "/opt/node/22/bin/node", nil, "bad site root"},
		{"root dot dot", "/home/acme/../etc", "/opt/node/20/bin/node", "/opt/node/22/bin/node", nil, "bad site root"},
		{"not a dir", "/home/acme/missing", "/opt/node/20/bin/node", "/opt/node/22/bin/node", nil, "isn't a directory"},
		{"bad binary", siteRoot, "/tmp/node", "/opt/node/22/bin/node", nil, "bad node binary"},
		{"same", siteRoot, "/opt/node/22/bin/node", "/opt/node/22/bin/node", nil, "same binary"},
		{"to missing", siteRoot, "/opt/node/20/bin/node", "/opt/node/24/bin/node", nil, "doesn't exist or isn't executable"},
		{"to not executable", siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node", func(h *fakeHost) {
			os.Chmod(filepath.Join(h.root, "opt/node/22/bin/node"), 0o644)
		}, "isn't executable"},
		{"nothing runs it", siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node", nil, "no supervisor program, systemd unit or cron line"},
		{"pm2 only", siteRoot, "/opt/node/20/bin/node", "/opt/node/22/bin/node", func(h *fakeHost) {
			h.write("home/acme/.pm2/dump.pm2", `[{"pm_cwd":"/home/acme/app","exec_interpreter":"/opt/node/20/bin/node"}]`, 0o644)
		}, "only pm2 runs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			h.installTree("20.18.1")
			h.installTree("22.12.0")
			h.write("home/acme/app/server.js", "", 0o644)
			if c.setup != nil {
				c.setup(h)
			}
			err := h.env.SwitchSite(context.Background(), c.root, c.from, c.to)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func defaultHost(t *testing.T, file, content string) *fakeHost {
	h := newHost(t)
	h.write("usr/bin/node", "#!fake\n", 0o755)
	h.write(file, content, 0o644)
	h.versions["/usr/bin/node"] = "20.18.1"
	h.versions["dpkg:nodejs"] = "20.18.1-1nodesource1"
	h.write("etc/supervisor/conf.d/app.conf", "[program:app]\ncommand=node /home/acme/app/server.js\n", 0o644)
	h.status["app"] = []string{"app   RUNNING   pid 10\n"}
	// A PHP worker doesn't run node and isn't restarted.
	h.write("etc/supervisor/conf.d/queue.conf", "[program:queue]\ncommand=/usr/bin/php /home/acme/site/artisan queue:work\n", 0o644)
	h.status["queue"] = []string{"queue   RUNNING   pid 11\n"}
	h.onCall = func(argv []string) {
		if strings.Join(argv, " ") == "/usr/bin/apt-get -q -y --allow-downgrades -o Dpkg::Options::=--force-confold install nodejs" {
			src := h.read(file)
			switch {
			case strings.Contains(src, "node_22.x"):
				h.versions["/usr/bin/node"] = "22.12.0"
			case strings.Contains(src, "node_20.x"):
				h.versions["/usr/bin/node"] = "20.18.1"
			}
		}
	}
	return h
}

func TestDefaultSwitch(t *testing.T) {
	sources := []struct{ file, content string }{
		{"etc/apt/sources.list.d/nodesource.list", "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main\n"},
		{"etc/apt/sources.list.d/nodesource.sources", "Types: deb\nURIs: https://deb.nodesource.com/node_20.x\nSuites: nodistro\nComponents: main\nSigned-By: /usr/share/keyrings/nodesource.gpg\n"},
	}
	for _, s := range sources {
		t.Run(filepath.Base(s.file), func(t *testing.T) {
			h := defaultHost(t, s.file, s.content)
			ctx := context.Background()
			if err := h.env.DefaultSwitch(ctx, "20", "22"); err != nil {
				t.Fatalf("switch: %v\n%s", err, h.out.String())
			}
			if got := h.read(s.file); got != strings.ReplaceAll(s.content, "node_20.x", "node_22.x") {
				t.Fatalf("source = %q", got)
			}
			for _, want := range []string{"/usr/bin/apt-get -q update", "/usr/bin/supervisorctl restart app:*"} {
				if !h.called(want) {
					t.Errorf("no %q in %v", want, h.calls)
				}
			}
			if h.called("/usr/bin/supervisorctl restart queue:*") {
				t.Error("restarted the PHP worker")
			}
			m, _ := filepath.Glob(filepath.Join(h.root, "var/backups/node-default/*/manifest.json"))
			if len(m) != 1 || !strings.Contains(h.read(strings.TrimPrefix(m[0], h.root)), `"nodejs": "20.18.1-1nodesource1"`) {
				t.Fatalf("manifest = %v", m)
			}
			// Again: nothing to do.
			h.out.Reset()
			if err := h.env.DefaultSwitch(ctx, "20", "22"); err != nil || !strings.Contains(h.out.String(), "nothing to do") {
				t.Fatalf("again: %v\n%s", err, h.out.String())
			}
		})
	}
}

func TestDefaultSwitchRollsBack(t *testing.T) {
	file := "etc/apt/sources.list.d/nodesource.list"
	content := "deb https://deb.nodesource.com/node_20.x nodistro main\n"
	h := defaultHost(t, file, content)
	h.status["app"] = []string{"app   RUNNING   pid 10\n", "app   BACKOFF   Exited too quickly\n"}
	err := h.env.DefaultSwitch(context.Background(), "20", "22")
	if err == nil || !strings.Contains(err.Error(), "isn't RUNNING") || !strings.Contains(err.Error(), "were put back") {
		t.Fatalf("err = %v\n%s", err, h.out.String())
	}
	if got := h.read(file); got != content {
		t.Fatalf("source = %q", got)
	}
	if !h.called("/usr/bin/apt-get -q -y --allow-downgrades -o Dpkg::Options::=--force-confold install nodejs=20.18.1-1nodesource1") {
		t.Fatalf("no reinstall in %v", h.calls)
	}
}

func TestDefaultSwitchRefusals(t *testing.T) {
	cases := []struct {
		name, content, node, want string
	}{
		{"wrong major", "deb https://deb.nodesource.com/node_20.x nodistro main\n", "18.20.4", "is v18.20.4, not Node.js 20"},
		{"source names another", "deb https://deb.nodesource.com/node_18.x nodistro main\n", "20.18.1", "doesn't name deb.nodesource.com/node_20.x"},
		{"not nodesource", "deb https://deb.example.com/node nodistro main\n", "20.18.1", "doesn't name deb.nodesource.com/node_20.x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := defaultHost(t, "etc/apt/sources.list.d/nodesource.list", c.content)
			h.versions["/usr/bin/node"] = c.node
			err := h.env.DefaultSwitch(context.Background(), "20", "22")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if h.called("/usr/bin/apt-get") {
				t.Fatal("ran apt-get")
			}
		})
	}
	t.Run("no source", func(t *testing.T) {
		h := newHost(t)
		if err := h.env.DefaultSwitch(context.Background(), "20", "22"); err == nil || !strings.Contains(err.Error(), "no NodeSource apt source") {
			t.Fatal(err)
		}
	})
}

func TestReport(t *testing.T) {
	h := newHost(t)
	h.write("usr/bin/node", "#!fake\n", 0o755)
	h.versions["/usr/bin/node"] = "22.11.0"
	h.versions["dpkg:nodejs"] = "22.11.0-1nodesource1"
	h.installTree("20.18.1")
	h.write("opt/node/.22.previous/include/node/node_version.h", header("22.1.0"), 0o644)
	h.write("etc/supervisor/conf.d/app.conf", "[program:app]\ncommand=/opt/node/20/bin/node /home/acme/app/server.js --token=abc123\n", 0o644)
	h.write("etc/systemd/system/api.service", "[Service]\nExecStart=/usr/bin/env node /srv/api.js\n", 0o644)
	h.write("var/spool/cron/crontabs/acme", "PATH=/usr/bin\n* * * * * /home/acme/.nvm/versions/node/v18.20.4/bin/node /home/acme/x.js "+strings.Repeat("y", 400)+"\n", 0o600)
	r, err := h.env.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	var got map[string]any
	json.Unmarshal(b, &got)
	want := `{"default":{"major":"22","path":"/usr/bin/node","source":"nodesource","version":"22.11.0"},"installs":[{"major":"20","path":"/opt/node/20","version":"20.18.1"}]`
	if !strings.HasPrefix(string(mustJSON(got)), want) {
		t.Fatalf("report = %s", mustJSON(got))
	}
	uses := r.Uses
	if len(uses) != 3 {
		t.Fatalf("uses = %+v", uses)
	}
	if uses[0] != (Use{Kind: "supervisor", File: "/etc/supervisor/conf.d/app.conf", Name: "app", Binary: "/opt/node/20/bin/node", Line: "command=/opt/node/20/bin/node /home/acme/app/server.js --token=[REDACTED]"}) {
		t.Errorf("supervisor use = %+v", uses[0])
	}
	if uses[1].Kind != "systemd" || uses[1].Name != "api.service" || uses[1].Binary != "node" {
		t.Errorf("systemd use = %+v", uses[1])
	}
	if uses[2].Kind != "cron" || uses[2].Name != "" || uses[2].Binary != "/home/acme/.nvm/versions/node/v18.20.4/bin/node" || len(uses[2].Line) != 300 {
		t.Errorf("cron use = %+v", uses[2])
	}

	// No default node.
	os.Remove(filepath.Join(h.root, "usr/bin/node"))
	r, _ = h.env.Report(context.Background())
	if r.Default != nil {
		t.Fatalf("default = %+v", r.Default)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestRewritePath(t *testing.T) {
	cases := []struct{ line, from, to, want string }{
		{`environment=PATH="/opt/node/20/bin:/usr/bin",X="1"`, "/opt/node/20/bin", "/opt/node/22/bin", `environment=PATH="/opt/node/22/bin:/usr/bin",X="1"`},
		{`Environment=PATH=/usr/bin:/bin`, "/usr/bin", "/opt/node/22/bin", `Environment=PATH=/opt/node/22/bin:/usr/bin:/bin`},
		{`Environment=PATH=/opt/node/22/bin:/usr/bin:/bin`, "/opt/node/22/bin", "/usr/bin", `Environment=PATH=/usr/bin:/bin`},
		{`Environment="NODE_ENV=production" "PATH=/opt/node/20/bin:/bin"`, "/opt/node/20/bin", "/usr/bin", `Environment="NODE_ENV=production" "PATH=/usr/bin:/bin"`},
		{`Environment=MYPATH=/opt/node/20/bin`, "/opt/node/20/bin", "/usr/bin", `Environment=MYPATH=/opt/node/20/bin`},
	}
	for _, c := range cases {
		if got, _ := rewritePath(c.line, c.from, c.to); got != c.want {
			t.Errorf("rewritePath(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestBinaries(t *testing.T) {
	cases := map[string][]string{
		"command=/opt/node/20/bin/node server.js":           {"/opt/node/20/bin/node"},
		"ExecStart=-/usr/bin/node a.js":                     {"/usr/bin/node"},
		"* * * * * cd /srv && node x.js":                    {"node"},
		"command=/srv/node_modules/.bin/tsc":                nil,
		"command=/home/acme/my-node/run":                    nil,
		"command=/usr/bin/php /srv/node/artisan queue:work": nil,
	}
	for line, want := range cases {
		if got := binaries(line); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("binaries(%q) = %v, want %v", line, got, want)
		}
	}
}
