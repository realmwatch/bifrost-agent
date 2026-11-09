package phpops

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// host is a fake apt host: its package state changes as commands run.
type host struct {
	t         *testing.T
	root      string
	installed map[string]string
	status    string
	active    string
	enabled   string
	grepOut   string
	grepCode  int
	simExtra  string
	simCode   int
	calls     []string
	purged    bool
	reinstall bool
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{t: t, root: t.TempDir(), status: "ii ", active: "inactive", enabled: "disabled", grepCode: 1,
		installed: map[string]string{"php8.2": "8.2.1-1", "php8.2-cli": "8.2.1-1", "php8.2-common": "8.2.1-1", "php8.3-cli": "8.3.0-1"}}
	h.write("etc/os-release", "ID=ubuntu\n")
	h.write("etc/php/8.2/cli/php.ini", "memory_limit=1G\n")
	return h
}

func (h *host) write(p, content string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) env() *Env {
	return &Env{Runner: h, Root: h.root, Now: func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) }, Out: io.Discard}
}

func (h *host) Run(_ context.Context, c runner.Command) (int, error) {
	joined := strings.Join(c.Argv, " ")
	h.calls = append(h.calls, joined)
	out, code := "", 0
	switch {
	case strings.Contains(joined, "is-active"):
		out, code = h.active+"\n", 3
		if h.active == "active" {
			code = 0
		}
	case strings.Contains(joined, "is-enabled"):
		out, code = h.enabled+"\n", 1
		if h.enabled == "enabled" {
			code = 0
		}
	case strings.Contains(joined, "disable --now"):
	case c.Argv[0] == "/usr/bin/grep":
		out, code = h.grepOut, h.grepCode
	case c.Argv[0] == "/usr/bin/dpkg-query":
		for n, v := range h.installed {
			out += fmt.Sprintf("%s\t%s\t%s\n", h.status, n, v)
		}
	case c.Argv[0] == "/usr/bin/tar" && c.Argv[3] == "-cpf":
		if err := os.WriteFile(c.Argv[4], []byte("tar"), 0o600); err != nil {
			return -1, err
		}
	case c.Argv[0] == "/usr/bin/tar" && c.Argv[3] == "-xpf":
		h.write("etc/php/8.2/restored", "yes")
	case strings.HasPrefix(joined, "/usr/bin/apt-get -s purge"):
		for _, n := range c.Argv[3:] {
			out += "Purg " + n + " [1]\n"
		}
		out += h.simExtra
		code = h.simCode
	case strings.HasPrefix(joined, "/usr/bin/apt-get -s install"):
		code = h.simCode
		out = h.simExtra
		if code != 0 {
			_, _ = io.WriteString(c.Stderr, "E: Version '8.2.1-1' for 'php8.2' was not found\n")
		}
	case strings.Contains(joined, " purge "):
		h.purged = true
		for n := range h.installed {
			if strings.HasPrefix(n, "php8.2") {
				delete(h.installed, n)
			}
		}
	case strings.Contains(joined, " install "):
		h.reinstall = true
		for _, spec := range c.Argv[len(c.Argv)-3:] {
			n, v, _ := strings.Cut(spec, "=")
			h.installed[n] = v
		}
	default:
		h.t.Fatalf("unexpected command %q", joined)
	}
	if c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, out)
	}
	return code, nil
}

func (h *host) backupDir() string {
	return filepath.Join(h.root, "var/backups/php-remove/8.2/20261109T120000Z")
}

func TestRemoveBacksUpThenPurges(t *testing.T) {
	h := newHost(t)
	if err := h.env().Remove(context.Background(), "8.2"); err != nil {
		t.Fatal(err)
	}
	if !h.purged {
		t.Fatal("not purged")
	}
	manifest, err := os.ReadFile(filepath.Join(h.backupDir(), manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifest) != "php8.2\t8.2.1-1\nphp8.2-cli\t8.2.1-1\nphp8.2-common\t8.2.1-1\n" {
		t.Fatalf("manifest = %q", manifest)
	}
	info, err := os.Stat(h.backupDir())
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("backup dir: %v %v", info, err)
	}
	tarAt, purgeAt := -1, -1
	for i, c := range h.calls {
		if strings.Contains(c, "-cpf") {
			tarAt = i
		}
		if strings.Contains(c, " purge ") && !strings.Contains(c, " -s ") {
			purgeAt = i
		}
	}
	if tarAt < 0 || purgeAt < tarAt {
		t.Fatalf("backup must come before the purge: %v", h.calls)
	}
}

func TestRemoveRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*host)
		want  string
	}{
		{"fpm active", func(h *host) { h.active = "active" }, "php8.2-fpm is active"},
		{"fpm activating", func(h *host) { h.active = "activating" }, "php8.2-fpm is activating"},
		{"fpm enabled", func(h *host) { h.enabled = "enabled" }, "refused: php8.2-fpm is"},
		{"nginx socket", func(h *host) {
			h.write("etc/nginx/sites-enabled/app", "  fastcgi_pass unix:/run/php/php8.2-fpm.sock;\n")
		}, "/etc/nginx/sites-enabled/app:1"},
		{"apache handler", func(h *host) {
			h.write("etc/apache2/conf-enabled/app.conf", "SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n")
		}, "/etc/apache2/conf-enabled/app.conf:1"},
		{"php alternative", func(h *host) {
			h.write("etc/alternatives/.keep", "")
			if err := os.Symlink("/usr/bin/php8.2", filepath.Join(h.root, "etc/alternatives/php")); err != nil {
				t.Fatal(err)
			}
		}, "alternative points at /usr/bin/php8.2"},
		{"cron reference", func(h *host) { h.grepOut, h.grepCode = "/etc/cron.d/app\n", 0; h.write("etc/cron.d/app", "") }, "/etc/cron.d/app"},
		{"search fails", func(h *host) { h.grepCode = 2; h.write("etc/cron.d/app", "") }, "searching for references failed"},
		{"held", func(h *host) { h.status = "hi " }, "is held"},
		{"broken dpkg state", func(h *host) { h.status = "iF " }, "broken dpkg state"},
		{"removes unversioned packages", func(h *host) { h.simExtra = "Remv php-redis [6]\nRemv php-cli [2]\n" }, "must stay: php-cli, php-redis"},
		{"would install", func(h *host) { h.simExtra = "Inst php9.0 (1)\n" }, "would also install: php9.0"},
		{"simulation fails", func(h *host) { h.simCode = 100 }, "simulation exited with status 100"},
		{"nothing installed", func(h *host) { h.installed = map[string]string{"php8.3-cli": "1"} }, "no php8.2 packages"},
		{"not apt", func(h *host) { h.write("etc/os-release", "ID=rhel\n") }, "only supported on apt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			c.setup(h)
			err := h.env().Remove(context.Background(), "8.2")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if h.purged {
				t.Fatal("purged despite refusing")
			}
			if _, statErr := os.Stat(filepath.Join(h.root, "var/backups")); statErr == nil {
				t.Fatal("backed up despite refusing")
			}
		})
	}
}

func TestRemoveRejectsBadVersions(t *testing.T) {
	for _, v := range []string{"8", "8.2.1", "8.2;rm", "../8.2", ""} {
		if err := newHost(t).env().Remove(context.Background(), v); err == nil || !strings.Contains(err.Error(), "bad PHP version") {
			t.Fatalf("%q: err = %v", v, err)
		}
	}
}

func TestSiteConfigsIgnoreCommentsOtherVersionsAndShippedFiles(t *testing.T) {
	h := newHost(t)
	h.write("etc/nginx/sites-available/default", "#\tfastcgi_pass unix:/run/php/php8.2-fpm.sock;\n  fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n  x php8.20-fpm\n")
	h.write("etc/apache2/conf-available/php8.2-fpm.conf", "SetHandler proxy:unix:/run/php/php8.2-fpm.sock\n")
	if err := h.env().checkSiteConfigs(context.Background(), "8.2"); err != nil {
		t.Fatal(err)
	}
}

func TestSiteConfigsFollowEnabledLinks(t *testing.T) {
	h := newHost(t)
	h.write("etc/apache2/conf-available/php8.2-fpm.conf", "SetHandler proxy:unix:/run/php/php8.2-fpm.sock\n")
	h.write("etc/apache2/conf-enabled/.keep", "")
	if err := os.Symlink("../conf-available/php8.2-fpm.conf", filepath.Join(h.root, "etc/apache2/conf-enabled/php8.2-fpm.conf")); err != nil {
		t.Fatal(err)
	}
	if err := h.env().checkSiteConfigs(context.Background(), "8.2"); err == nil {
		t.Fatal("an enabled shipped config must count")
	}
}

func TestRestoreReinstallsExactVersionsAndConfig(t *testing.T) {
	h := newHost(t)
	if err := h.env().Remove(context.Background(), "8.2"); err != nil {
		t.Fatal(err)
	}
	if err := h.env().Restore(context.Background(), "8.2", ""); err != nil {
		t.Fatal(err)
	}
	if !h.reinstall || h.installed["php8.2-cli"] != "8.2.1-1" {
		t.Fatalf("not reinstalled: %v", h.installed)
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/php/8.2/restored")); err != nil {
		t.Fatal("config not restored")
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/php/8.2/cli/php.ini")); err == nil {
		t.Fatal("the config directory must be replaced, not merged")
	}
}

func TestRestoreFailsWhenARecordedVersionIsGone(t *testing.T) {
	h := newHost(t)
	if err := h.env().Remove(context.Background(), "8.2"); err != nil {
		t.Fatal(err)
	}
	h.simCode = 100
	err := h.env().Restore(context.Background(), "8.2", "")
	if err == nil || !strings.Contains(err.Error(), "no longer be available") || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("err = %v", err)
	}
	if h.reinstall {
		t.Fatal("must not install anything")
	}
}

func TestRestoreLeavesALiveVersionAlone(t *testing.T) {
	h := newHost(t)
	h.write("var/backups/php-remove/8.2/20200101T000000Z/packages.tsv", "php8.2-cli\t8.0.0-1\n")
	h.write("var/backups/php-remove/8.2/20200101T000000Z/etc-php.tar", "old")
	if err := h.env().Restore(context.Background(), "8.2", ""); err != nil {
		t.Fatal(err)
	}
	if h.reinstall {
		t.Fatal("a refused removal's rollback must not touch a live version")
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/php/8.2/cli/php.ini")); err != nil {
		t.Fatal("live config was touched")
	}
}

func TestRestoreWithoutABackup(t *testing.T) {
	if err := newHost(t).env().Restore(context.Background(), "8.2", ""); err != nil {
		t.Fatalf("nothing removed, so nothing to do: %v", err)
	}
	h := newHost(t)
	h.installed = map[string]string{}
	if err := h.env().Restore(context.Background(), "8.2", ""); err == nil || !strings.Contains(err.Error(), "no backup") {
		t.Fatalf("err = %v", err)
	}
	if err := newHost(t).env().Restore(context.Background(), "8.2", "20200101T000000Z"); err == nil || !strings.Contains(err.Error(), "no backup") {
		t.Fatalf("err = %v", err)
	}
	if err := newHost(t).env().Restore(context.Background(), "8.2", "../../etc"); err == nil || !strings.Contains(err.Error(), "bad backup name") {
		t.Fatalf("err = %v", err)
	}
}

func TestRestoreRefusesATamperedManifest(t *testing.T) {
	h := newHost(t)
	h.installed = map[string]string{}
	h.write("var/backups/php-remove/8.2/20200101T000000Z/packages.tsv", "openssh-server\t1.0-1\n")
	if err := h.env().Restore(context.Background(), "8.2", ""); err == nil || !strings.Contains(err.Error(), "bad line") {
		t.Fatalf("err = %v", err)
	}
}
