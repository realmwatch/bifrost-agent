package phpops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// fakeHost is an apt host with nginx, PHP 8.1 serving a site, and 8.3
// available from apt.
type fakeHost struct {
	t           *testing.T
	root        string
	installed   map[string]string
	candidates  map[string]string
	active      map[string]bool
	nginxCode   int
	curl        map[string]string // port → status ("" = no answer)
	altOnCLI    string            // the alternative an install moves php to
	fpmLog      string            // appended to the new FPM's log during the smoke check
	calls       []string
	simulateRem string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, root: t.TempDir(),
		installed: map[string]string{
			"php8.1": "1", "php8.1-fpm": "1", "php8.1-cli": "1", "php8.1-common": "1", "php8.1-mbstring": "1",
			"php8.1-redis": "1", "php8.1-json": "1",
		},
		candidates: map[string]string{
			"php8.1-fpm": "1", "php8.2-fpm": "2", "php8.3-fpm": "3", "php8.3-cli": "3", "php8.3-common": "3",
			"php8.3-mbstring": "3", "php8.3-redis": "3",
		},
		active: map[string]bool{"php8.1-fpm": true},
		curl:   map[string]string{"443": "200", "80": "301"},
	}
	h.write("etc/os-release", "ID=ubuntu\n", 0o644)
	h.write("etc/php/8.1/fpm/pool.d/www.conf", "[www]\nlisten = /run/php/php8.1-fpm.sock\n", 0o644)
	h.write("etc/php/8.1/fpm/pool.d/example.conf", "[example]\nlisten = /run/php/php8.1-fpm-example.sock\n", 0o640)
	h.write("etc/php/8.1/fpm/php.ini", "memory_limit = 512M\nupload_max_filesize = 64M\n; post_max_size = 1G\ndisplay_errors = Off\n", 0o644)
	h.write("etc/php/8.1/fpm/conf.d/99-custom.ini", "opcache.jit=tracing\n", 0o644)
	h.write("etc/php/8.1/cli/php.ini", "memory_limit = -1\n", 0o644)
	h.write("etc/php/8.1/cli/conf.d/.keep", "", 0o644)
	h.mkdir("etc/alternatives")
	h.symlink("/usr/bin/php8.1", "etc/alternatives/php")
	h.symlink("/usr/bin/phar8.1", "etc/alternatives/phar")
	h.mkdir("home/forge")

	site := `server {
    listen 443 ssl;
    server_name example.com www.example.com;
    root /home/forge/example.com/public;
    include forge-conf/example.com/server/*;
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
`
	h.write("etc/nginx/sites-available/example.com", site, 0o644)
	h.symlink("../sites-available/example.com", "etc/nginx/sites-enabled/example.com")
	// Another site in the same file, still on 8.1 after the switch.
	h.write("etc/nginx/sites-enabled/shared", `server {
    server_name other.example.com;
    root /home/forge/other.example.com/public;
    location ~ \.php$ { fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; }
}
server {
    server_name api.example.com;
    root /home/forge/api.example.com/public;
    location ~ \.php$ {
        # fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
`, 0o644)
	h.mkdir("home/forge/example.com/public")
	h.mkdir("home/forge/other.example.com/public")
	h.mkdir("home/forge/api.example.com/public")
	h.write("home/forge/example.com/.git/config", "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://deploy:secret@github.com/acme/app.git\n", 0o644)
	h.write("home/forge/example.com/composer.json", `{"require":{"php":"^8.1"},"config":{"platform":{"php":"8.1"}}}`, 0o644)
	h.write("home/forge/example.com/composer.lock", `{"packages":[{"name":"laravel/framework","require":{"php":"^8.1"}},{"name":"acme/no-php","require":{}},{"name":"laravel/framework","require":{"php":"^8.1"}}],"packages-dev":[{"name":"phpunit/phpunit","require":{"php":">=8.1"}}]}`, 0o644)
	h.write("var/spool/cron/crontabs/forge", "* * * * * php8.1 /home/forge/example.com/artisan schedule:run\n* * * * * php /home/forge/other.example.com/artisan schedule:run\n", 0o600)
	h.write("etc/supervisor/conf.d/worker-1.conf", "[program:worker-1]\ncommand=php /home/forge/example.com/artisan queue:work\n", 0o644)
	h.write("etc/systemd/system/horizon.service", "[Service]\nExecStart=/usr/bin/php8.1 /home/forge/example.com/artisan horizon\n", 0o644)
	h.write("etc/cron.d/backup", "0 3 * * * root /usr/bin/php7.4 /home/forge/example.com.old/backup.php\n", 0o644)
	return h
}

func (h *fakeHost) path(p string) string { return filepath.Join(h.root, p) }

func (h *fakeHost) mkdir(p string) {
	h.t.Helper()
	if err := os.MkdirAll(h.path(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) write(p, content string, mode os.FileMode) {
	h.t.Helper()
	h.mkdir(filepath.Dir(p))
	if err := os.WriteFile(h.path(p), []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(h.path(p), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) read(p string) string {
	h.t.Helper()
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *fakeHost) symlink(target, p string) {
	h.t.Helper()
	h.mkdir(filepath.Dir(p))
	_ = os.Remove(h.path(p))
	if err := os.Symlink(target, h.path(p)); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) env() *Env {
	return &Env{Runner: h, Root: h.root, Now: func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }, Out: io.Discard}
}

func (h *fakeHost) Run(_ context.Context, c runner.Command) (int, error) {
	joined := strings.Join(c.Argv, " ")
	h.calls = append(h.calls, joined)
	out, code := "", 0
	a := c.Argv
	switch {
	case a[0] == "/usr/bin/dpkg-query":
		for n, v := range h.installed {
			out += fmt.Sprintf("ii \t%s\t%s\n", n, v)
		}
	case joined == "/usr/bin/apt-cache pkgnames php":
		for n := range h.candidates {
			out += n + "\n"
		}
		out += "php8.0-fpm\n" // known but no candidate
	case a[0] == "/usr/bin/apt-cache" && a[1] == "policy":
		for _, n := range a[2:] {
			cand := h.candidates[n]
			if cand == "" {
				cand = "(none)"
			}
			out += n + ":\n  Installed: (none)\n  Candidate: " + cand + "\n  Version table:\n"
		}
	case a[0] == "/usr/bin/systemctl" && (a[1] == "is-active" || a[1] == "is-enabled"):
		if !h.active[a[len(a)-1]] {
			code = 3
		}
	case strings.HasPrefix(joined, "/usr/bin/apt-get -s install"):
		out = h.simulateRem
	case a[0] == "/usr/bin/apt-get" && contains(a, "install"):
		for _, n := range a[len(aptOptions)+5:] {
			h.installed[n] = "3"
		}
		h.write("etc/php/8.3/fpm/pool.d/www.conf", "[www]\nlisten = /run/php/php8.3-fpm.sock\n", 0o644)
		h.write("etc/php/8.3/fpm/php.ini", "memory_limit = 128M\nupload_max_filesize = 2M\ndisplay_errors = Off\n", 0o644)
		h.write("etc/php/8.3/cli/php.ini", "memory_limit = -1\n", 0o644)
		if h.altOnCLI != "" {
			h.symlink(h.altOnCLI, "etc/alternatives/php")
			h.symlink("/usr/bin/phar8.3", "etc/alternatives/phar")
		}
	case a[0] == "/usr/bin/update-alternatives":
		h.symlink(a[3], "etc/alternatives/"+a[2])
	case a[0] == "/usr/sbin/php-fpm8.3":
	case joined == "/usr/bin/systemctl enable --now php8.3-fpm":
		h.active["php8.3-fpm"] = true
	case a[0] == "/usr/sbin/nginx":
		if strings.Contains(h.read("etc/nginx/sites-available/example.com"), "php8.3") {
			code = h.nginxCode // the broken config is the switched one
		}
		if code != 0 {
			_, _ = io.WriteString(c.Stderr, "nginx: [emerg] bad config\n")
		}
	case a[0] == "/usr/bin/systemctl", a[0] == "/usr/bin/supervisorctl":
	case a[0] == "/usr/bin/curl":
		port := strings.Split(a[len(a)-2], ":")[1]
		if h.fpmLog != "" {
			f, _ := os.OpenFile(h.path("var/log/php8.3-fpm.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
			_, _ = f.WriteString(h.fpmLog)
			f.Close()
		}
		out = h.curl[port]
		if out == "" {
			out, code = "000", 7
		}
	default:
		h.t.Fatalf("unexpected command %q", joined)
	}
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, out)
	}
	return code, nil
}

func (h *fakeHost) ran(prefix string) bool {
	for _, c := range h.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestSitesReport(t *testing.T) {
	h := newFakeHost(t)
	h.installed["php8.3-cli"] = "3"
	r, err := h.env().Sites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Versions.Installed, []string{"8.1", "8.3"}) || r.Versions.Alternative != "8.1" ||
		!reflect.DeepEqual(r.Versions.Installable, []string{"8.1", "8.2", "8.3"}) ||
		!reflect.DeepEqual(r.Versions.FPM, map[string]FPMState{"8.1": {Active: true, Enabled: true}}) {
		t.Fatalf("versions = %+v", r.Versions)
	}
	if len(r.Sites) != 3 || r.Truncated {
		t.Fatalf("sites = %+v", r.Sites)
	}
	got := r.Sites[1]
	want := Site{
		Root: "/home/forge/example.com", ServerNames: []string{"example.com", "www.example.com"},
		Vhosts: []string{"/etc/nginx/sites-enabled/example.com"}, PHP: "8.1", Repo: "github.com/acme/app",
		RequirePHP: "^8.1", PlatformPHP: "8.1", Forge: true,
		LockPHP: []LockPHP{{Package: "laravel/framework", Constraint: "^8.1"}, {Package: "phpunit/phpunit", Constraint: ">=8.1"}},
		CLI: []CLIUse{
			{Kind: "cron", File: "/var/spool/cron/crontabs/forge", PHP: "8.1"},
			{Kind: "supervisor", File: "/etc/supervisor/conf.d/worker-1.conf", PHP: "php"},
			{Kind: "systemd", File: "/etc/systemd/system/horizon.service", PHP: "8.1"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("site =\n%+v\nwant\n%+v", got, want)
	}
	if r.Sites[0].Root != "/home/forge/api.example.com" || r.Sites[0].PHP != "8.1" {
		t.Fatalf("the commented-out socket must not count: %+v", r.Sites[0])
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"require_php":"^8.1"`) || !strings.Contains(string(b), `"installable":["8.1","8.2","8.3"]`) {
		t.Fatalf("json = %s %v", b, err)
	}
}

func TestLockPHPIsCapped(t *testing.T) {
	h := newFakeHost(t)
	var pkgs []string
	for i := 0; i < MaxLockPHP+5; i++ {
		pkgs = append(pkgs, fmt.Sprintf(`{"name":"acme/p%d","require":{"php":">=8.0"}}`, i))
	}
	h.write("home/forge/example.com/composer.lock", `{"packages":[`+strings.Join(pkgs, ",")+`]}`, 0o644)
	got, truncated := h.env().lockPHP("/home/forge/example.com")
	if len(got) != MaxLockPHP || !truncated {
		t.Fatalf("len = %d, truncated = %v", len(got), truncated)
	}
	if got, truncated := h.env().lockPHP("/home/forge/other.example.com"); len(got) != 0 || got == nil || truncated {
		t.Fatalf("no lock: %v %v", got, truncated)
	}
}

func TestSitesRefusesNonApt(t *testing.T) {
	h := newFakeHost(t)
	h.write("etc/os-release", "ID=rhel\n", 0o644)
	if _, err := h.env().Sites(context.Background()); err == nil || !strings.Contains(err.Error(), "only supported on apt") {
		t.Fatalf("err = %v", err)
	}
}

func TestNormaliseRepo(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:acme/app.git":              "github.com/acme/app",
		"https://user:tok@GitHub.com/acme/app.git": "github.com/acme/app",
		"ssh://git@gitlab.example.com:2222/a/b":    "gitlab.example.com/a/b",
		"/srv/repos/app.git":                       "",
		"https://example.com/a b":                  "",
	} {
		if got := NormaliseRepo(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestInstallCopiesExtensionsPoolsAndSettings(t *testing.T) {
	h := newFakeHost(t)
	h.altOnCLI = "/usr/bin/php8.3"
	if err := h.env().Install(context.Background(), "8.3", "8.1"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for n, v := range h.installed {
		if v == "3" {
			got = append(got, n)
		}
	}
	sort.Strings(got)
	if want := []string{"php8.3-cli", "php8.3-common", "php8.3-fpm", "php8.3-mbstring", "php8.3-redis"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("installed %v, want %v (no bare metapackage, no json on 8.x)", got, want)
	}
	if s := h.read("etc/php/8.3/fpm/pool.d/example.conf"); !strings.Contains(s, "php8.3-fpm-example.sock") {
		t.Fatalf("pool not ported: %q", s)
	}
	if info, _ := os.Stat(h.path("etc/php/8.3/fpm/pool.d/example.conf")); info.Mode().Perm() != 0o640 {
		t.Fatalf("pool mode = %v", info.Mode())
	}
	if s := h.read("var/backups/php-install/8.3/20261115T120000Z/pool.d/www.conf"); !strings.Contains(s, "php8.3-fpm.sock") {
		t.Fatalf("packaged pool not backed up: %q", s)
	}
	if s := h.read("etc/php/8.3/fpm/conf.d/99-custom.ini"); s != "opcache.jit=tracing\n" {
		t.Fatalf("override not copied: %q", s)
	}
	ported := h.read("etc/php/8.3/fpm/conf.d/" + PortedIni)
	if !strings.Contains(ported, "memory_limit = 512M") || !strings.Contains(ported, "upload_max_filesize = 64M") ||
		strings.Contains(ported, "post_max_size") || strings.Contains(ported, "display_errors") {
		t.Fatalf("ported settings = %q", ported)
	}
	if _, err := os.Stat(h.path("etc/php/8.3/cli/conf.d/" + PortedIni)); err == nil {
		t.Fatal("cli settings are equal; nothing to port")
	}
	if !h.active["php8.3-fpm"] {
		t.Fatal("new FPM not started")
	}
	for alt, want := range map[string]string{"php": "/usr/bin/php8.1", "phar": "/usr/bin/phar8.1"} {
		if target, _ := os.Readlink(h.path("etc/alternatives/" + alt)); target != want {
			t.Fatalf("%s alternative = %q, want it put back to %q", alt, target, want)
		}
	}
	if !h.ran("/usr/bin/update-alternatives --set php /usr/bin/php8.1") {
		t.Fatalf("calls = %v", h.calls)
	}
}

func TestInstallLeavesUnmovedAlternativesAlone(t *testing.T) {
	h := newFakeHost(t)
	if err := h.env().Install(context.Background(), "8.3", "8.1"); err != nil {
		t.Fatal(err)
	}
	if h.ran("/usr/bin/update-alternatives") {
		t.Fatal("nothing moved, so nothing to put back")
	}
}

func TestInstallRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeHost)
		want  string
	}{
		{"already installed", func(h *fakeHost) { h.installed["php8.3-fpm"] = "3" }, "already installed"},
		{"missing extension", func(h *fakeHost) { delete(h.candidates, "php8.3-redis") }, "no package for: php8.3-redis"},
		{"tcp pool", func(h *fakeHost) {
			h.write("etc/php/8.1/fpm/pool.d/tcp.conf", "[tcp]\nlisten = 127.0.0.1:9000\n", 0o644)
		}, "listens on 127.0.0.1:9000"},
		{"would remove", func(h *fakeHost) { h.simulateRem = "Remv libapache2-mod-php8.1 [1]\n" }, "would remove: libapache2-mod-php8.1"},
		{"nothing to copy", func(h *fakeHost) { h.installed = map[string]string{} }, "no php8.1 packages"},
		{"same version", func(*fakeHost) {}, "SAME"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newFakeHost(t)
			c.setup(h)
			version, want := "8.3", c.want
			if want == "SAME" {
				version, want = "8.1", "the one installed"
			}
			err := h.env().Install(context.Background(), version, "8.1")
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
			if h.ran("/usr/bin/apt-get -q") {
				t.Fatal("installed despite refusing")
			}
		})
	}
}

func readyToSwitch(t *testing.T) *fakeHost {
	h := newFakeHost(t)
	h.installed["php8.3-fpm"] = "3"
	h.active["php8.3-fpm"] = true
	h.write("var/log/php8.3-fpm.log", "[15-Nov-2026 11:00:00] ERROR: an old error\n", 0o644)
	return h
}

func TestSwitchMovesOnlyThatSite(t *testing.T) {
	h := readyToSwitch(t)
	if err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.1", "8.3"); err != nil {
		t.Fatal(err)
	}
	vhost := h.read("etc/nginx/sites-available/example.com")
	if !strings.Contains(vhost, "php8.3-fpm.sock") || strings.Contains(vhost, "php8.1") {
		t.Fatalf("vhost = %q", vhost)
	}
	if fi, _ := os.Lstat(h.path("etc/nginx/sites-enabled/example.com")); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the enabled link must stay a link")
	}
	if s := h.read("etc/nginx/sites-enabled/shared"); strings.Contains(s, "8.3") {
		t.Fatalf("another site changed: %q", s)
	}
	cron := h.read("var/spool/cron/crontabs/forge")
	if cron != "* * * * * php8.3 /home/forge/example.com/artisan schedule:run\n* * * * * php /home/forge/other.example.com/artisan schedule:run\n" {
		t.Fatalf("crontab = %q", cron)
	}
	if info, _ := os.Stat(h.path("var/spool/cron/crontabs/forge")); info.Mode().Perm() != 0o600 {
		t.Fatalf("crontab mode = %v", info.Mode())
	}
	if s := h.read("etc/supervisor/conf.d/worker-1.conf"); !strings.Contains(s, "command=php8.3 /home/forge/example.com/artisan") {
		t.Fatalf("supervisor = %q", s)
	}
	if s := h.read("etc/systemd/system/horizon.service"); !strings.Contains(s, "ExecStart=/usr/bin/php8.3 /home/forge") {
		t.Fatalf("unit = %q", s)
	}
	if s := h.read("etc/cron.d/backup"); strings.Contains(s, "8.3") {
		t.Fatalf("a longer path that starts with the root changed: %q", s)
	}
	for _, want := range []string{"/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx", "/usr/bin/supervisorctl reread", "/usr/bin/supervisorctl update",
		"/usr/bin/systemctl daemon-reload", "/usr/bin/systemctl restart horizon.service", "/usr/bin/curl"} {
		if !h.ran(want) {
			t.Fatalf("didn't run %q: %v", want, h.calls)
		}
	}
	if target, _ := os.Readlink(h.path("etc/alternatives/php")); target != "/usr/bin/php8.1" {
		t.Fatalf("alternative = %q", target)
	}
	manifest := h.read("var/backups/php-switch/20261115T120000Z/manifest.tsv")
	if strings.Count(manifest, "\n") != 4 || !strings.Contains(manifest, "/var/spool/cron/crontabs/forge\t0600") {
		t.Fatalf("manifest = %q", manifest)
	}

	// Rolling back is the same operation the other way.
	if err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.3", "8.1"); err != nil {
		t.Fatal(err)
	}
	if s := h.read("etc/nginx/sites-available/example.com"); !strings.Contains(s, "php8.1-fpm.sock") {
		t.Fatalf("not rolled back: %q", s)
	}
}

func TestSwitchPutsEverythingBackOnFailure(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeHost)
		want  string
	}{
		{"nginx -t", func(h *fakeHost) { h.nginxCode = 1 }, "nginx -t failed"},
		{"5xx", func(h *fakeHost) { h.curl["443"] = "502" }, "answered HTTP 502"},
		{"no answer", func(h *fakeHost) { h.curl = map[string]string{} }, "didn't answer"},
		{"fpm errors", func(h *fakeHost) { h.fpmLog = "[15-Nov-2026 12:00:01] ERROR: unable to bind\n" }, "logged errors"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := readyToSwitch(t)
			before := map[string]string{}
			for _, p := range []string{"etc/nginx/sites-available/example.com", "var/spool/cron/crontabs/forge", "etc/supervisor/conf.d/worker-1.conf", "etc/systemd/system/horizon.service"} {
				before[p] = h.read(p)
			}
			c.setup(h)
			err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.1", "8.3")
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "put back") {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			for p, s := range before {
				if h.read(p) != s {
					t.Fatalf("%s not put back", p)
				}
			}
			if info, _ := os.Stat(h.path("var/spool/cron/crontabs/forge")); info.Mode().Perm() != 0o600 {
				t.Fatalf("crontab mode = %v", info.Mode())
			}
			// The proposal's rollback (the switch the other way) then has
			// nothing to do, and must not move the bare php lines.
			h.calls = nil
			if err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.3", "8.1"); err != nil {
				t.Fatalf("rollback err = %v", err)
			}
			if h.ran("/usr/sbin/nginx") {
				t.Fatal("the rollback had nothing to do")
			}
			for p, s := range before {
				if h.read(p) != s {
					t.Fatalf("%s changed by the rollback", p)
				}
			}
		})
	}
}

func TestSwitchIsANoOpWhenAlreadyMoved(t *testing.T) {
	h := readyToSwitch(t)
	if err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.1", "8.3"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.env().Switch(context.Background(), "/home/forge/example.com", "8.1", "8.3"); err != nil {
		t.Fatal(err)
	}
	if h.ran("/usr/sbin/nginx") {
		t.Fatal("nothing to do, nothing reloaded")
	}
}

func TestSwitchRefusals(t *testing.T) {
	cases := []struct {
		name, root, from, to string
		setup                func(*fakeHost)
		want                 string
	}{
		{"relative root", "home/forge/example.com", "8.1", "8.3", nil, "bad site root"},
		{"dotdot", "/home/forge/../forge/example.com", "8.1", "8.3", nil, "bad site root"},
		{"shell", "/home/forge/x;rm", "8.1", "8.3", nil, "bad site root"},
		{"missing dir", "/home/forge/nope", "8.1", "8.3", nil, "isn't a directory"},
		{"no vhost", "/home/forge", "8.1", "8.3", nil, "no enabled nginx vhost"},
		{"wrong from", "/home/forge/example.com", "7.4", "8.3", nil, "doesn't serve"},
		{"to not running", "/home/forge/example.com", "8.1", "8.3", func(h *fakeHost) { h.active["php8.3-fpm"] = false }, "isn't running"},
		{"same", "/home/forge/example.com", "8.1", "8.1", nil, "same version"},
		{"bad version", "/home/forge/example.com", "8.1", "8", nil, "bad PHP version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := readyToSwitch(t)
			if c.setup != nil {
				c.setup(h)
			}
			err := h.env().Switch(context.Background(), c.root, c.from, c.to)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if _, err := os.Stat(h.path("var/backups/php-switch")); err == nil {
				t.Fatal("backed up despite refusing")
			}
		})
	}
}
