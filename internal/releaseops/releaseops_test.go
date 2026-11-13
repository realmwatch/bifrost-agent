package releaseops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// host is a fake Ubuntu 22.04 host upgraded from 20.04.
type fakeHost struct {
	t          *testing.T
	root       string
	pkgs       map[string][2]string // name → version, maintainer
	local      map[string]bool      // apt list marks these [installed,local]
	policy     string
	files      map[string][]string // package → files (dpkg -L)
	reachable  map[string]bool
	updateCode int
	updateErr  string
	simExtra   string
	calls      []string
	purged     []string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, root: t.TempDir(), reachable: map[string]bool{}, local: map[string]bool{}}
	h.write("etc/os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n")
	h.write("etc/apt/sources.list.d/pgdg.list", "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.example.org/pub/repos/apt/ focal-pgdg main\n")
	h.write("etc/apt/sources.list.d/nodesource.list", "deb https://deb.example.com/node_16.x focal main\ndeb-src https://deb.example.com/node_16.x focal main\n")
	h.write("etc/apt/sources.list.d/esm.list", "deb https://esm.example.com/apps/ubuntu jammy-apps-security main\ndeb https://esm.example.com/apps/ubuntu focal-apps-security main\n")
	h.write("etc/apt/sources.list.d/current.list", "deb http://archive.example.com/ubuntu jammy main\n")
	h.write("etc/apt/sources.list.d/vendor.list", "# deb https://packages.example.net/repos/vendor-ubuntu-focal-prod jammy main # disabled on upgrade to jammy\n")
	h.reachable["http://apt.example.org/pub/repos/apt/dists/jammy-pgdg/InRelease"] = true
	h.pkgs = map[string][2]string{
		"libssl1.1":   {"1.1.1f-1ubuntu2.24+esm6", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"},
		"libwebp6":    {"0.6.1-2ubuntu0.20.04.3", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"},
		"nessusagent": {"10.7.0", "Example Vendor <support@example.com>"},
		"libpq5":      {"17.5-1.pgdg20.04+1", "Debian PostgreSQL Maintainers <team+postgresql@tracker.debian.org>"},
		"libssl3":     {"3.0.2-0ubuntu1.30", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"},
		"redis-tools": {"6:8.0.6-1rl1~focal1", "Example <redis@example.com>"},
	}
	h.local = map[string]bool{"libssl1.1": true, "libwebp6": true, "nessusagent": true}
	h.policy = "libpq5:\n  Installed: 17.5-1.pgdg20.04+1\n  Candidate: 17.5-1.pgdg20.04+1\n  Version table:\n" +
		"     17.6-1.pgdg22.04+1 500\n        500 http://apt.example.org/pub/repos/apt jammy-pgdg/main amd64 Packages\n" +
		" *** 17.5-1.pgdg20.04+1 500\n        500 http://apt.example.org/pub/repos/apt focal-pgdg/main amd64 Packages\n        100 /var/lib/dpkg/status\n" +
		"     14.24-0ubuntu0.22.04.1 500\n        500 http://archive.example.com/ubuntu jammy-updates/main amd64 Packages\n" +
		"redis-tools:\n  Installed: 6:8.0.6-1rl1~focal1\n  Candidate: 6:8.0.6-1rl1~focal1\n  Version table:\n" +
		" *** 6:8.0.6-1rl1~focal1 500\n        500 https://packages.example.io/deb focal/main amd64 Packages\n        100 /var/lib/dpkg/status\n"
	h.files = map[string][]string{
		"libssl1.1": {"/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1", "/usr/share/doc/libssl1.1"},
		"libwebp6":  {"/usr/lib/x86_64-linux-gnu/libwebp.so.6.0.2"},
		"libpq5":    {"/usr/lib/x86_64-linux-gnu/libpq.so.5.17"},
	}
	h.process(1258, "php-fpm8.3", "0::/system.slice/php8.3-fpm.service", "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "/usr/lib/x86_64-linux-gnu/libpq.so.5.17", "/usr/lib/x86_64-linux-gnu/libc.so.6")
	h.process(900, "bash", "0::/user.slice/user-1000.slice/session-3.scope", "/usr/lib/x86_64-linux-gnu/libc.so.6")
	return h
}

func (h *fakeHost) write(p, content string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) read(p string) string {
	b, err := os.ReadFile(filepath.Join(h.root, p))
	if err != nil {
		return ""
	}
	return string(b)
}

func (h *fakeHost) process(pid int, comm, cgroup string, libs ...string) {
	var maps strings.Builder
	for i, l := range libs {
		fmt.Fprintf(&maps, "7f%04x000-7f%04x100 r-xp 00000000 08:01 %d %s\n", i, i, 100+i, l)
	}
	h.write(fmt.Sprintf("proc/%d/maps", pid), maps.String())
	h.write(fmt.Sprintf("proc/%d/comm", pid), comm+"\n")
	h.write(fmt.Sprintf("proc/%d/cgroup", pid), cgroup+"\n")
}

func (h *fakeHost) env() *Env {
	return &Env{
		Runner: h, Root: h.root, Out: &strings.Builder{},
		Now:       func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) },
		Reachable: func(_ context.Context, url string) bool { return h.reachable[url] },
	}
}

func (h *fakeHost) Run(_ context.Context, c runner.Command) (int, error) {
	joined := strings.Join(c.Argv, " ")
	h.calls = append(h.calls, joined)
	out, errOut, code := "", "", 0
	switch {
	case c.Argv[0] == "/usr/bin/dpkg-query":
		names := make([]string, 0, len(h.pkgs))
		for n := range h.pkgs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out += fmt.Sprintf("ii \t%s\t%s\t%s\n", n, h.pkgs[n][0], h.pkgs[n][1])
		}
	case joined == "/usr/bin/apt list --installed":
		out = "Listing...\n"
		for n, p := range h.pkgs {
			mark := "[installed]"
			if h.local[n] {
				mark = "[installed,local]"
			}
			out += fmt.Sprintf("%s/now %s amd64 %s\n", n, p[0], mark)
		}
	case strings.HasPrefix(joined, "/usr/bin/apt-cache policy"):
		out = h.policy
	case c.Argv[0] == "/usr/bin/dpkg" && c.Argv[1] == "-L":
		out = strings.Join(h.files[c.Argv[2]], "\n") + "\n"
	case strings.HasPrefix(joined, "/usr/bin/apt-get -q update"):
		code, errOut = h.updateCode, h.updateErr
	case strings.HasPrefix(joined, "/usr/bin/apt-get -s purge "):
		for _, n := range c.Argv[3:] {
			out += "Purg " + n + " [1]\n"
		}
		out += h.simExtra
	case strings.HasPrefix(joined, "/usr/bin/apt-get -q -y "):
		for i, a := range c.Argv {
			if a == "purge" {
				for _, n := range c.Argv[i+1:] {
					delete(h.pkgs, n)
					h.purged = append(h.purged, n)
				}
			}
		}
	default:
		h.t.Fatalf("unexpected command %q", joined)
	}
	if c.Stdout != nil {
		fmt.Fprint(c.Stdout, out)
	}
	if c.Stderr != nil {
		fmt.Fprint(c.Stderr, errOut)
	}
	return code, nil
}

func TestLeftoversReportsWhatTheUpgradeLeftBehind(t *testing.T) {
	h := newFakeHost(t)

	r, err := h.env().Leftovers(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if r.Codename != "jammy" {
		t.Errorf("codename %q", r.Codename)
	}
	got := []string{}
	for _, s := range r.Sources {
		got = append(got, fmt.Sprintf("%s %s %s→%s %s", s.File, s.URI, s.Suite, s.NewSuite, s.Action))
	}
	want := []string{
		"esm.list https://esm.example.com/apps/ubuntu focal-apps-security→jammy-apps-security retarget",
		"nodesource.list https://deb.example.com/node_16.x focal→jammy disable",
		"pgdg.list http://apt.example.org/pub/repos/apt/ focal-pgdg→jammy-pgdg retarget",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if fmt.Sprint(r.Obsolete) != "[{libssl1.1 1.1.1f-1ubuntu2.24+esm6 older } {libwebp6 0.6.1-2ubuntu0.20.04.3 focal }]" {
		t.Errorf("obsolete %v", r.Obsolete)
	}
	if fmt.Sprint(r.Disabled) != "[{vendor.list deb https://packages.example.net/repos/vendor-ubuntu-focal-prod jammy main}]" {
		t.Errorf("disabled %v", r.Disabled)
	}
	if fmt.Sprint(r.Local) != "[{nessusagent 10.7.0  }]" {
		t.Errorf("local %v", r.Local)
	}
	if fmt.Sprint(r.OldBuilds) != "[{libpq5 17.5-1.pgdg20.04+1 focal 17.6-1.pgdg22.04+1} {redis-tools 6:8.0.6-1rl1~focal1 focal }]" {
		t.Errorf("old builds %v", r.OldBuilds)
	}
	if fmt.Sprint(r.UsedBy) != "[{1258 php-fpm8.3 php8.3-fpm.service /usr/lib/x86_64-linux-gnu/libpq.so.5.17 libpq5} {1258 php-fpm8.3 php8.3-fpm.service /usr/lib/x86_64-linux-gnu/libssl.so.1.1 libssl1.1}]" {
		t.Errorf("used by %v", r.UsedBy)
	}
}

func TestBuiltFor(t *testing.T) {
	h := host{distro: "ubuntu", codename: "jammy", version: 22.04}
	for version, want := range map[string]string{
		"0.6.1-2ubuntu0.20.04.3":                "focal",
		"1.7.3-1+ubuntu20.04.1+deb.sury.org+2":  "focal",
		"17.5-1.pgdg20.04+1":                    "focal",
		"6:8.0.6-1rl1~focal1":                   "focal",
		"0.4.2-3ubuntu0.20.04.1~esm1":           "focal",
		"1.2.3-1ubuntu0.18.04.1":                "bionic",
		"3.0.2-0ubuntu1.30":                     "",
		"1.2.2-2ubuntu0.22.04.2":                "",
		"17.6-1.pgdg22.04+1":                    "",
		"8.3.36-1+ubuntu22.04.1+deb.sury.org+1": "",
		"1.1.1f-1ubuntu2.24+esm6":               "",
		"2:9.1.0-1ubuntu1~noble1":               "",
	} {
		if got := h.builtFor(version); got != want {
			t.Errorf("builtFor(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestReplacementsKeepTheEpochAndNeverGoBack(t *testing.T) {
	for _, c := range []struct {
		installed, replacement string
		ok                     bool
	}{
		{"17.5-1.pgdg20.04+1", "17.6-1.pgdg22.04+1", true},
		{"1.7.3-1+ubuntu20.04.1+deb.sury.org+2", "1.7.3-1ubuntu2", true},
		{"17.5-1.pgdg20.04+1", "14.24-0ubuntu0.22.04.1", false},
		{"6:8.0.6-1rl1~focal1", "5:6.0.16-1ubuntu1.2+esm1", false},
		{"6:8.0.6-1rl1~focal1", "6:8.0.7-1rl1~jammy1", true},
	} {
		if got := acceptable(c.installed, c.replacement); got != c.ok {
			t.Errorf("acceptable(%s, %s) = %v", c.installed, c.replacement, got)
		}
	}
}

func TestRetargetChangesOnlyTheSuiteAfterARefreshProvesIt(t *testing.T) {
	h := newFakeHost(t)

	if err := h.env().Retarget(context.Background(), "pgdg.list"); err != nil {
		t.Fatal(err)
	}

	if got := h.read("etc/apt/sources.list.d/pgdg.list"); got != "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.example.org/pub/repos/apt/ jammy-pgdg main\n" {
		t.Errorf("file now %q", got)
	}
	backups, _ := filepath.Glob(filepath.Join(h.root, "var/backups/apt-sources/*/pgdg.list"))
	if len(backups) != 1 {
		t.Fatalf("backups %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); !strings.Contains(string(b), "focal-pgdg") {
		t.Errorf("backup %q", b)
	}
	var update string
	for _, c := range h.calls {
		if strings.HasPrefix(c, "/usr/bin/apt-get -q update") {
			update = c
		}
	}
	if !strings.Contains(update, "Dir::Etc::sourcelist=/dev/null") || !strings.Contains(update, "Dir::Etc::sourceparts=") {
		t.Errorf("refresh %q", update)
	}
}

func TestRetargetKeepsTheFileWhenTheSourceDoesNotOfferTheRelease(t *testing.T) {
	for _, c := range []struct {
		code int
		err  string
	}{
		{100, "E: The repository 'https://deb.example.com/node_16.x jammy Release' does not have a Release file."},
		{0, "W: GPG error: … NO_PUBKEY 1655A0AB68576280"},
	} {
		h := newFakeHost(t)
		h.updateCode, h.updateErr = c.code, c.err
		before := h.read("etc/apt/sources.list.d/nodesource.list")

		err := h.env().Retarget(context.Background(), "nodesource.list")

		if err == nil || !strings.Contains(err.Error(), "doesn't offer jammy") {
			t.Fatalf("got %v", err)
		}
		if h.read("etc/apt/sources.list.d/nodesource.list") != before {
			t.Error("the file changed")
		}
	}
}

func TestRetargetDropsALineThatWouldDuplicateAnother(t *testing.T) {
	h := newFakeHost(t)

	if err := h.env().Retarget(context.Background(), "esm.list"); err != nil {
		t.Fatal(err)
	}
	if got := h.read("etc/apt/sources.list.d/esm.list"); got != "deb https://esm.example.com/apps/ubuntu jammy-apps-security main\n" {
		t.Errorf("file now %q", got)
	}
}

func TestRetargetDeb822(t *testing.T) {
	h := newFakeHost(t)
	h.write("etc/apt/sources.list.d/redis.sources", "Types: deb\nURIs: https://packages.example.io/deb\nSuites: focal\nComponents: main\nSigned-By: /usr/share/keyrings/redis.gpg\n")

	if err := h.env().Retarget(context.Background(), "redis.sources"); err != nil {
		t.Fatal(err)
	}
	if got := h.read("etc/apt/sources.list.d/redis.sources"); got != "Types: deb\nURIs: https://packages.example.io/deb\nSuites: jammy\nComponents: main\nSigned-By: /usr/share/keyrings/redis.gpg\n" {
		t.Errorf("file now %q", got)
	}
}

func TestRetargetRefusesAFileWithNothingToChangeAndBadNames(t *testing.T) {
	h := newFakeHost(t)
	for _, file := range []string{"current.list", "../sources.list", "x.conf", "-rf.list"} {
		if err := h.env().Retarget(context.Background(), file); err == nil {
			t.Errorf("%s accepted", file)
		}
	}
	if h.read("etc/apt/sources.list.d/current.list") != "deb http://archive.example.com/ubuntu jammy main\n" {
		t.Error("current.list changed")
	}
}

func TestDisableAndRestore(t *testing.T) {
	h := newFakeHost(t)
	e := h.env()
	before := h.read("etc/apt/sources.list.d/nodesource.list")

	if err := e.Disable(context.Background(), "nodesource.list"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/apt/sources.list.d/nodesource.list")); err == nil {
		t.Fatal("still there")
	}
	if err := e.Restore(context.Background(), "nodesource.list"); err != nil {
		t.Fatal(err)
	}
	if h.read("etc/apt/sources.list.d/nodesource.list") != before {
		t.Error("not restored")
	}
	if err := e.Restore(context.Background(), "current.list"); err != nil {
		t.Errorf("restoring a file with no backup that is in place: %v", err)
	}
	if err := e.Restore(context.Background(), "gone.list"); err == nil {
		t.Error("restored a file with no backup")
	}
}

func TestRemoveObsoleteRefusesWhileInUse(t *testing.T) {
	h := newFakeHost(t)

	err := h.env().RemoveObsolete(context.Background(), []string{"libssl1.1", "libwebp6"})

	if err == nil || !strings.Contains(err.Error(), "php-fpm8.3 (pid 1258, php8.3-fpm.service) loads /usr/lib/x86_64-linux-gnu/libssl.so.1.1 from libssl1.1") {
		t.Fatalf("got %v", err)
	}
	if len(h.purged) != 0 {
		t.Error("purged anyway")
	}
}

func TestRemoveObsoletePurgesLeftoversAndSkipsTheRest(t *testing.T) {
	h := newFakeHost(t)
	h.process(1258, "php-fpm8.3", "0::/system.slice/php8.3-fpm.service", "/usr/lib/x86_64-linux-gnu/libssl.so.3")
	out := &strings.Builder{}
	e := h.env()
	e.Out = out

	if err := e.RemoveObsolete(context.Background(), []string{"libssl1.1", "libwebp6", "nessusagent", "libssl3"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.purged, " ") != "libssl1.1 libwebp6" {
		t.Errorf("purged %v", h.purged)
	}
	for _, line := range []string{"Skipped nessusagent", "Skipped libssl3", "libwebp6 0.6.1-2ubuntu0.20.04.3 (built for focal)"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
}

func TestRemoveObsoleteRefusesWhenThePurgeTakesMore(t *testing.T) {
	h := newFakeHost(t)
	h.process(1258, "php-fpm8.3", "0::/system.slice/php8.3-fpm.service")
	h.simExtra = "Remv libpq5 [17.5-1.pgdg20.04+1]\n"

	err := h.env().RemoveObsolete(context.Background(), []string{"libssl1.1"})
	if err == nil || !strings.Contains(err.Error(), "would also remove packages that must stay: libpq5") {
		t.Fatalf("got %v", err)
	}
	if len(h.purged) != 0 {
		t.Error("purged anyway")
	}
}

func TestOnlyAptHosts(t *testing.T) {
	h := newFakeHost(t)
	h.write("etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	if _, err := h.env().Leftovers(context.Background()); err == nil || !strings.Contains(err.Error(), "only supported on apt hosts") {
		t.Fatalf("got %v", err)
	}
}
