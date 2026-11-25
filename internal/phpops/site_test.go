package phpops

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// siteHost is a host with three sites: example.com (a symlinked vhost,
// a cron line, a queue worker and a systemd unit), app.example.com (a
// regular file in conf.d) and two sites sharing one file.
type siteHost struct {
	t         *testing.T
	root      string
	running   map[string]bool // supervisor programs
	active    map[string]bool // systemd units
	enabled   map[string]bool
	nginxCode int
	calls     []string
}

const exampleRoot = "/home/acme/example.com"

const workerConf = "[program:example-worker]\ncommand=php /home/acme/example.com/artisan queue:work\nautostart=true\nautorestart=true\n\n[program:other-worker]\ncommand=php /home/acme/other.example.com/artisan queue:work\n"

const crontab = "* * * * * php /home/acme/example.com/artisan schedule:run >> /dev/null 2>&1\n* * * * * php /home/acme/other.example.com/artisan schedule:run\n"

func newSiteHost(t *testing.T) *siteHost {
	t.Helper()
	h := &siteHost{t: t, root: t.TempDir(),
		running: map[string]bool{"example-worker": true, "other-worker": true},
		active:  map[string]bool{"example-reverb.service": true},
		enabled: map[string]bool{"example-reverb.service": true},
	}
	for _, d := range []string{"home/acme/example.com/public", "home/acme/app.example.com/public", "home/acme/other.example.com/public", "home/acme/api.example.com/public"} {
		h.mkdir(d)
	}
	h.write("etc/nginx/sites-available/example.com", `server {
    listen 443 ssl;
    server_name example.com www.example.com;
    root /home/acme/example.com/public;
    location ~ \.php$ { fastcgi_pass unix:/run/php/php8.3-fpm-example.sock; }
}
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
`, 0o644)
	h.symlink("../sites-available/example.com", "etc/nginx/sites-enabled/example.com")
	h.write("etc/nginx/conf.d/app.conf", "server {\n    server_name app.example.com;\n    root /home/acme/app.example.com/public;\n}\n", 0o640)
	h.write("etc/nginx/sites-enabled/shared", "server {\n    server_name other.example.com;\n    root /home/acme/other.example.com/public;\n    location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }\n}\nserver {\n    server_name api.example.com;\n    root /home/acme/api.example.com/public;\n}\n", 0o644)
	h.write("etc/php/8.3/fpm/pool.d/example.conf", "[example]\nlisten = /run/php/php8.3-fpm-example.sock\n", 0o644)
	h.write("etc/php/8.3/fpm/pool.d/www.conf", "[www]\nlisten = /run/php/php8.3-fpm.sock\n", 0o644)
	h.write("var/spool/cron/crontabs/acme", crontab, 0o600)
	h.write("etc/supervisor/conf.d/workers.conf", workerConf, 0o644)
	h.write("etc/systemd/system/example-reverb.service", "[Service]\nWorkingDirectory=/home/acme/example.com\nExecStart=/usr/bin/php artisan reverb:start\n", 0o644)
	return h
}

func (h *siteHost) path(p string) string { return filepath.Join(h.root, p) }

func (h *siteHost) mkdir(p string) {
	h.t.Helper()
	if err := os.MkdirAll(h.path(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *siteHost) write(p, content string, mode os.FileMode) {
	h.t.Helper()
	h.mkdir(filepath.Dir(p))
	if err := os.WriteFile(h.path(p), []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *siteHost) read(p string) string {
	h.t.Helper()
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *siteHost) exists(p string) bool {
	_, err := os.Lstat(h.path(p))
	return err == nil
}

func (h *siteHost) symlink(target, p string) {
	h.t.Helper()
	h.mkdir(filepath.Dir(p))
	if err := os.Symlink(target, h.path(p)); err != nil {
		h.t.Fatal(err)
	}
}

func (h *siteHost) env() *Env {
	return &Env{Runner: h, Root: h.root, Now: func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }, Out: io.Discard}
}

func (h *siteHost) Run(_ context.Context, c runner.Command) (int, error) {
	a := c.Argv
	joined := strings.Join(a, " ")
	h.calls = append(h.calls, joined)
	out, code := "", 0
	switch {
	case joined == "/usr/sbin/nginx -t":
		if !h.exists("etc/nginx/sites-enabled/example.com") {
			code = h.nginxCode // the broken config is the changed one
		}
	case joined == "/usr/bin/systemctl reload nginx":
	case a[0] == "/usr/bin/supervisorctl" && (a[1] == "reread" || a[1] == "update"):
	case a[0] == "/usr/bin/supervisorctl":
		name := strings.TrimSuffix(a[2], ":*")
		switch a[1] {
		case "status":
			if h.running[name] {
				out = name + ":" + name + "_00 RUNNING pid 1, uptime 1:00:00\n"
			} else {
				out, code = name+":"+name+"_00 STOPPED\n", 3
			}
		case "stop":
			h.running[name] = false
		case "start":
			h.running[name] = true
		}
	case a[0] == "/usr/bin/systemctl":
		unit := a[len(a)-1]
		switch a[1] {
		case "is-active":
			if !h.active[unit] {
				code = 3
			}
		case "is-enabled":
			if !h.enabled[unit] {
				code = 1
			}
		case "disable":
			h.active[unit], h.enabled[unit] = false, false
		case "enable":
			h.enabled[unit] = true
		case "start":
			h.active[unit] = true
		default:
			h.t.Fatalf("unexpected %q", joined)
		}
	default:
		h.t.Fatalf("unexpected command %q", joined)
	}
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, out)
	}
	return code, nil
}

func TestSitePlanListsWhatDisableChanges(t *testing.T) {
	h := newSiteHost(t)
	p, err := h.env().PlanSite(context.Background(), "disable", exampleRoot, "/etc/nginx/sites-enabled/example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal != "" || len(p.Vhosts) != 1 || p.Vhosts[0].Kind != "symlink" || p.Vhosts[0].Target != "../sites-available/example.com" {
		t.Fatalf("plan = %+v", p)
	}
	if len(p.Cron) != 1 || !strings.Contains(p.Cron[0].Line, "example.com/artisan schedule:run") {
		t.Fatalf("cron = %+v", p.Cron)
	}
	if len(p.Supervisor) != 1 || p.Supervisor[0].Program != "example-worker" || !p.Supervisor[0].Running {
		t.Fatalf("supervisor = %+v", p.Supervisor)
	}
	if len(p.Units) != 1 || p.Units[0].Unit != "example-reverb.service" {
		t.Fatalf("units = %+v", p.Units)
	}
	if len(p.Pools) != 1 || p.Pools[0].File != "/etc/php/8.3/fpm/pool.d/example.conf" {
		t.Fatalf("pools = %+v", p.Pools)
	}
	if len(p.Drift) != 0 || p.Disabled {
		t.Fatalf("drift = %+v", p)
	}
}

func TestDisableThenEnableASymlinkedSite(t *testing.T) {
	h := newSiteHost(t)
	ctx := context.Background()
	if err := h.env().DisableSite(ctx, exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if h.exists("etc/nginx/sites-enabled/example.com") || !h.exists("etc/nginx/sites-available/example.com") {
		t.Fatal("the link should be gone and the vhost kept")
	}
	if got := h.read("var/spool/cron/crontabs/acme"); got != CronMarker+"* * * * * php /home/acme/example.com/artisan schedule:run >> /dev/null 2>&1\n* * * * * php /home/acme/other.example.com/artisan schedule:run\n" {
		t.Fatalf("crontab = %q", got)
	}
	if info, _ := os.Stat(h.path("var/spool/cron/crontabs/acme")); info.Mode().Perm() != 0o600 {
		t.Fatalf("crontab mode = %v", info.Mode())
	}
	if got := h.read("etc/supervisor/conf.d/workers.conf"); !strings.Contains(got, "[program:example-worker]\ncommand=php /home/acme/example.com/artisan queue:work\nautostart=false\n") || strings.Count(got, "autostart") != 1 {
		t.Fatalf("supervisor = %q", got)
	}
	if h.running["example-worker"] || !h.running["other-worker"] {
		t.Fatalf("running = %v", h.running)
	}
	if h.active["example-reverb.service"] || h.enabled["example-reverb.service"] {
		t.Fatal("the unit should be disabled and stopped")
	}
	if !h.exists("etc/nginx/sites-enabled/shared") || !h.exists("etc/nginx/conf.d/app.conf") {
		t.Fatal("other sites changed")
	}
	recordDir := h.path(SiteRecordDir)
	if entries, _ := os.ReadDir(recordDir); len(entries) != 1 {
		t.Fatalf("records = %v", entries)
	}

	// The dry run of either now says it's disabled, with no drift.
	p, _ := h.env().PlanSite(ctx, "enable", exampleRoot, "")
	if !p.Disabled || len(p.Drift) != 0 || len(p.Vhosts) != 1 || len(p.Cron) != 1 {
		t.Fatalf("enable plan = %+v", p)
	}

	if err := h.env().EnableSite(ctx, exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(h.path("etc/nginx/sites-enabled/example.com")); err != nil || target != "../sites-available/example.com" {
		t.Fatalf("link = %q, %v", target, err)
	}
	if got := h.read("var/spool/cron/crontabs/acme"); got != crontab {
		t.Fatalf("crontab = %q", got)
	}
	if got := h.read("etc/supervisor/conf.d/workers.conf"); got != workerConf {
		t.Fatalf("supervisor = %q", got)
	}
	if !h.running["example-worker"] || !h.active["example-reverb.service"] || !h.enabled["example-reverb.service"] {
		t.Fatal("the worker and unit should be back")
	}
	if entries, _ := os.ReadDir(recordDir); len(entries) != 0 {
		t.Fatalf("the record should be gone: %v", entries)
	}
}

func TestDisableInsertsAutostartWhereThereWasNone(t *testing.T) {
	h := newSiteHost(t)
	conf := "[program:example-worker]\ncommand=php /home/acme/example.com/artisan horizon\n"
	h.write("etc/supervisor/conf.d/workers.conf", conf, 0o644)
	if err := h.env().DisableSite(context.Background(), exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if got := h.read("etc/supervisor/conf.d/workers.conf"); got != "[program:example-worker]\nautostart=false\ncommand=php /home/acme/example.com/artisan horizon\n" {
		t.Fatalf("supervisor = %q", got)
	}
	if err := h.env().EnableSite(context.Background(), exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if got := h.read("etc/supervisor/conf.d/workers.conf"); got != conf {
		t.Fatalf("supervisor = %q", got)
	}
}

func TestDisableMovesARegularFileInConfD(t *testing.T) {
	h := newSiteHost(t)
	ctx := context.Background()
	if err := h.env().DisableSite(ctx, "/home/acme/app.example.com", "/etc/nginx/conf.d/app.conf"); err != nil {
		t.Fatal(err)
	}
	if h.exists("etc/nginx/conf.d/app.conf") {
		t.Fatal("the file should be out of conf.d")
	}
	if got := h.read("etc/nginx/bifrost-disabled/app.conf"); !strings.Contains(got, "app.example.com") {
		t.Fatalf("held = %q", got)
	}
	if err := h.env().EnableSite(ctx, "/home/acme/app.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if !h.exists("etc/nginx/conf.d/app.conf") || h.exists("etc/nginx/bifrost-disabled/app.conf") {
		t.Fatal("the file should be back")
	}
	if info, _ := os.Stat(h.path("etc/nginx/conf.d/app.conf")); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestDisableRefusals(t *testing.T) {
	cases := []struct {
		name, root string
		setup      func(*siteHost)
		want       string
	}{
		{"a shared vhost", "/home/acme/other.example.com", func(*siteHost) {}, "also serves /home/acme/api.example.com"},
		{"a default server", exampleRoot, func(h *siteHost) {
			s := strings.Replace(h.read("etc/nginx/sites-available/example.com"), "listen 443 ssl;", "listen 443 ssl default_server;", 1)
			h.write("etc/nginx/sites-available/example.com", s, 0o644)
		}, "default_server"},
		{"nothing serves it", "/home/acme/nothing.example.com", func(h *siteHost) { h.mkdir("home/acme/nothing.example.com") }, "no enabled nginx vhost"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newSiteHost(t)
			c.setup(h)
			err := h.env().DisableSite(context.Background(), c.root, "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if !h.exists("etc/nginx/sites-enabled/shared") || !h.exists("etc/nginx/sites-enabled/example.com") || h.read("var/spool/cron/crontabs/acme") != crontab {
				t.Fatal("changed something despite refusing")
			}
		})
	}
	h := newSiteHost(t)
	for _, bad := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/../x", "relative"} {
		if err := h.env().DisableSite(context.Background(), exampleRoot, bad); err == nil || !strings.Contains(err.Error(), "bad vhost") {
			t.Fatalf("vhost %q: err = %v", bad, err)
		}
	}
}

func TestDisablePutsEverythingBackWhenNginxTestFails(t *testing.T) {
	h := newSiteHost(t)
	h.nginxCode = 1
	err := h.env().DisableSite(context.Background(), exampleRoot, "")
	if err == nil || !strings.Contains(err.Error(), "nginx -t failed") || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("err = %v", err)
	}
	if target, _ := os.Readlink(h.path("etc/nginx/sites-enabled/example.com")); target != "../sites-available/example.com" {
		t.Fatalf("link not put back: %q", target)
	}
	if h.read("var/spool/cron/crontabs/acme") != crontab || !h.running["example-worker"] || !h.active["example-reverb.service"] {
		t.Fatal("changed something after nginx -t failed")
	}
	if h.exists(SiteRecordDir) {
		if entries, _ := os.ReadDir(h.path(SiteRecordDir)); len(entries) != 0 {
			t.Fatal("wrote a record for a failed disable")
		}
	}
}

func TestEnableWithoutARestoreRecord(t *testing.T) {
	h := newSiteHost(t)
	ctx := context.Background()
	// Disabled by hand: link removed and the cron line marked.
	if err := os.Remove(h.path("etc/nginx/sites-enabled/example.com")); err != nil {
		t.Fatal(err)
	}
	h.write("var/spool/cron/crontabs/acme", CronMarker+crontab, 0o600)

	p, err := h.env().PlanSite(ctx, "enable", exampleRoot, "/etc/nginx/sites-available/example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal != "" || len(p.Vhosts) != 1 || p.Vhosts[0].Path != "/etc/nginx/sites-enabled/example.com" || !strings.Contains(strings.Join(p.Notes, " "), "no restore record") {
		t.Fatalf("plan = %+v", p)
	}
	if err := h.env().EnableSite(ctx, exampleRoot, "/etc/nginx/sites-available/example.com"); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(h.path("etc/nginx/sites-enabled/example.com")); target != "/etc/nginx/sites-available/example.com" {
		t.Fatalf("link = %q", target)
	}
	if h.read("var/spool/cron/crontabs/acme") != crontab {
		t.Fatal("the marked cron line should be back")
	}
}

func TestDriftIsReported(t *testing.T) {
	h := newSiteHost(t)
	ctx := context.Background()
	if err := h.env().DisableSite(ctx, exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	// A hosting panel links it again.
	h.symlink("../sites-available/example.com", "etc/nginx/sites-enabled/example.com")
	for _, action := range []string{"disable", "enable"} {
		p, err := h.env().PlanSite(ctx, action, exampleRoot, "")
		if err != nil {
			t.Fatal(err)
		}
		if !p.Disabled || len(p.Drift) != 1 || !strings.Contains(p.Drift[0], "/etc/nginx/sites-enabled/example.com") {
			t.Fatalf("%s plan = %+v", action, p)
		}
	}
	// Disabling again takes it out once more, and enable then restores it.
	if err := h.env().DisableSite(ctx, exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if h.exists("etc/nginx/sites-enabled/example.com") {
		t.Fatal("still linked")
	}
	if err := h.env().EnableSite(ctx, exampleRoot, ""); err != nil {
		t.Fatal(err)
	}
	if !h.exists("etc/nginx/sites-enabled/example.com") || h.read("var/spool/cron/crontabs/acme") != crontab {
		t.Fatal("not restored")
	}
}
