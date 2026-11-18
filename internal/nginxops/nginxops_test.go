package nginxops

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/runner"
)

const mainConfText = `user www-data;
events { worker_connections 768; }
http {
	http2 on;
	include /etc/nginx/conf.d/*.conf;
	include sites-enabled/*;
}
stream {
	server { listen 9000; proxy_pass 127.0.0.1:9001; }
}
`

const siteA = `# a site with "quoted { braces }" in a comment
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2 default_server;
	listen 443 quic reuseport;
	http2 on;
	server_name example.com "www.example.com";
	include snippets/h2.conf;
}
server {
	listen 80;
	include snippets/h2.conf;
}
`

const snippet = "listen 8443 ssl\thttp2;\n"

func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// tree builds a host: nginx.conf, a site enabled through a symlink, a
// snippet two servers include, and an empty conf.d.
func tree(t *testing.T) (*Env, *runner.Fake, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	write(t, root, mainConf, mainConfText)
	write(t, root, "/etc/nginx/sites-available/a", siteA)
	write(t, root, "/etc/nginx/snippets/h2.conf", snippet)
	write(t, root, "/usr/sbin/nginx", "")
	if err := os.MkdirAll(filepath.Join(root, "/etc/nginx/sites-enabled"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/a", filepath.Join(root, "/etc/nginx/sites-enabled/a")); err != nil {
		t.Fatal(err)
	}
	fake := &runner.Fake{Default: &runner.Response{}}
	out := &bytes.Buffer{}
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	return &Env{Runner: fake, Root: root, Out: out, Now: func() time.Time { now = now.Add(time.Second); return now }}, fake, out
}

func TestPlanFindsEveryHTTP2AndLeavesQUICAlone(t *testing.T) {
	e, _, _ := tree(t)
	p, err := e.HTTP2Plan()
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{File: mainConf, Line: 4, Before: "\thttp2 on;", After: "\thttp2 off;"},
		{File: "/etc/nginx/sites-enabled/a", Line: 3, Before: "\tlisten 443 ssl http2;", After: "\tlisten 443 ssl;"},
		{File: "/etc/nginx/sites-enabled/a", Line: 4, Before: "\tlisten [::]:443 ssl http2 default_server;", After: "\tlisten [::]:443 ssl default_server;"},
		{File: "/etc/nginx/sites-enabled/a", Line: 6, Before: "\thttp2 on;", After: "\thttp2 off;"},
		{File: "/etc/nginx/snippets/h2.conf", Line: 1, Before: "listen 8443 ssl\thttp2;", After: "listen 8443 ssl;"},
	}
	if !reflect.DeepEqual(p.Changes, want) {
		t.Errorf("changes:\n got %+v\nwant %+v", p.Changes, want)
	}
	if p.FilesRead != 3 || len(p.Restorable) != 0 {
		t.Errorf("files read %d, restorable %v", p.FilesRead, p.Restorable)
	}
}

func TestOffThenRestore(t *testing.T) {
	e, fake, out := tree(t)
	ctx := context.Background()
	if err := e.HTTP2Off(ctx); err != nil {
		t.Fatalf("off: %v\n%s", err, out)
	}
	if got := fake.Argvs(); !reflect.DeepEqual(got, []string{"/usr/sbin/nginx -t", "/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx"}) {
		t.Errorf("commands: %v", got)
	}
	site := read(t, e.Root, "/etc/nginx/sites-available/a")
	if strings.Contains(site, "http2;") || strings.Contains(site, "http2 on") || !strings.Contains(site, "listen 443 quic reuseport;") {
		t.Errorf("site after off:\n%s", site)
	}
	if link, err := os.Readlink(filepath.Join(e.Root, "/etc/nginx/sites-enabled/a")); err != nil || link != "../sites-available/a" {
		t.Errorf("the sites-enabled symlink was replaced: %q %v", link, err)
	}
	if info, _ := os.Stat(filepath.Join(e.Root, "/etc/nginx/sites-available/a")); info.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "-\tlisten 443 ssl http2;\n+\tlisten 443 ssl;") {
		t.Errorf("no diff in the output:\n%s", out)
	}

	// Again: nothing left to change, and no new backup.
	if err := e.HTTP2Off(ctx); err != nil || !strings.Contains(out.String(), "already off") {
		t.Fatalf("second off: %v\n%s", err, out)
	}
	p, _ := e.HTTP2Plan()
	if len(p.Changes) != 0 || len(p.Restorable) != 1 || len(p.Restorable[0].Changes) != 5 {
		t.Fatalf("plan after off: %+v", p)
	}

	if err := e.HTTP2Restore(ctx); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if got := read(t, e.Root, "/etc/nginx/sites-available/a"); got != siteA {
		t.Errorf("site after restore:\n%s", got)
	}
	if got := read(t, e.Root, mainConf) + read(t, e.Root, "/etc/nginx/snippets/h2.conf"); got != mainConfText+snippet {
		t.Errorf("nginx.conf and snippet after restore:\n%s", got)
	}
	out.Reset()
	if err := e.HTTP2Restore(ctx); err != nil || !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("second restore: %v %s", err, out)
	}
}

func TestOffPutsEverythingBackWhenNginxTestFails(t *testing.T) {
	e, fake, out := tree(t)
	fake.Queue = map[string][]runner.Response{"/usr/sbin/nginx -t": {{}, {ExitCode: 1, Stderr: "nginx: [emerg] something"}}}
	err := e.HTTP2Off(context.Background())
	if err == nil || !strings.Contains(err.Error(), "every file was put back") || !strings.Contains(err.Error(), "[emerg]") {
		t.Fatalf("got %v\n%s", err, out)
	}
	if got := read(t, e.Root, "/etc/nginx/sites-available/a"); got != siteA {
		t.Errorf("site not put back:\n%s", got)
	}
	if got := fake.Argvs(); !reflect.DeepEqual(got, []string{"/usr/sbin/nginx -t", "/usr/sbin/nginx -t", "/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx"}) {
		t.Errorf("commands: %v", got)
	}
	if p, _ := e.HTTP2Plan(); len(p.Restorable) != 0 {
		t.Errorf("a put-back change is still restorable: %+v", p.Restorable)
	}
}

func TestOffRefusesWhenNginxAlreadyFailsItsTest(t *testing.T) {
	e, fake, _ := tree(t)
	fake.Queue = map[string][]runner.Response{"/usr/sbin/nginx -t": {{ExitCode: 1, Stderr: "nginx: [emerg] already broken"}}}
	err := e.HTTP2Off(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already fails its test") {
		t.Fatalf("got %v", err)
	}
	if read(t, e.Root, "/etc/nginx/sites-available/a") != siteA {
		t.Error("a file changed")
	}
	if p, _ := e.HTTP2Plan(); len(p.Restorable) != 0 {
		t.Errorf("a backup was made: %+v", p.Restorable)
	}
}

func TestRestoreRefusesWhenALineChangedSince(t *testing.T) {
	e, _, _ := tree(t)
	ctx := context.Background()
	if err := e.HTTP2Off(ctx); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(read(t, e.Root, "/etc/nginx/snippets/h2.conf"), "8443", "9443", 1)
	write(t, e.Root, "/etc/nginx/snippets/h2.conf", edited)
	before := read(t, e.Root, "/etc/nginx/sites-available/a")
	err := e.HTTP2Restore(ctx)
	if err == nil || !strings.Contains(err.Error(), "h2.conf:1 has changed since") {
		t.Fatalf("got %v", err)
	}
	if read(t, e.Root, "/etc/nginx/sites-available/a") != before {
		t.Error("the refused restore changed a file")
	}
}

func TestDefaultShadows(t *testing.T) {
	e, _, out := tree(t)
	write(t, e.Root, packageDefault, "server {\n\tlisten 80;\n\tserver_name localhost;\n}\n")
	if err := e.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "WARNING: /etc/nginx/conf.d/default.conf (from nginx.org's package) is now the default server for *:80, ahead of /etc/nginx/sites-enabled/a:10") {
		t.Errorf("no warning:\n%s", out)
	}

	// The host's own default_server keeps it.
	out.Reset()
	write(t, e.Root, "/etc/nginx/sites-available/a", strings.Replace(siteA, "listen 80;", "listen 80 default_server;", 1))
	if err := e.Check(context.Background()); err != nil || strings.Contains(out.String(), "WARNING") {
		t.Errorf("got %v\n%s", err, out)
	}
}

func TestTokenizeAndAddresses(t *testing.T) {
	toks, err := tokenize([]byte("a \"b ; c\" # d { e\nf;"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		got = append(got, tk.text)
	}
	if !reflect.DeepEqual(got, []string{"a", "b ; c", "f", ";"}) {
		t.Errorf("tokens: %q", got)
	}
	if _, err := tokenize([]byte(`a "b;`)); err == nil {
		t.Error("an unterminated quote was accepted")
	}
	for in, want := range map[string]string{"80": "*:80", "0.0.0.0:80": "*:80", "[::]:443": "[::]:443", "[::]": "[::]:80", "example.com": "example.com:80", "127.0.0.1:8080": "127.0.0.1:8080"} {
		if got := listenAddress(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
