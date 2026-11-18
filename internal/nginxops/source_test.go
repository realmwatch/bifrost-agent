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

const (
	ppaVersion = "1.28.0-1+ubuntu22.04.1+deb.sury.org+1"
	orgVersion = "1.31.9-1~jammy"
	dpkgNginx  = "/usr/bin/dpkg-query -W -f ${Version} nginx"
	ppaConf    = "load_module modules/ngx_http_brotli_filter_module.so;\nload_module modules/ngx_http_brotli_static_module.so;\ninclude /etc/nginx/modules-enabled/*.conf;\nevents {}\nhttp {\n\tinclude sites-enabled/*;\n}\n"
	ppaList    = "deb https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu/ jammy main\n"
	aptSim     = "Remv libnginx-mod-http-geoip [" + ppaVersion + "]\nInst nginx [" + ppaVersion + "] (" + orgVersion + " nginx.org [amd64])\nConf nginx (" + orgVersion + " nginx.org [amd64])\n"
)

func ppaHost(t *testing.T, release string) (*Env, *runner.Fake, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	write(t, root, "/etc/os-release", "ID=ubuntu\nVERSION_ID=\""+release+"\"\nVERSION_CODENAME=jammy\nPRETTY_NAME=\"Ubuntu "+release+" LTS\"\n")
	write(t, root, mainConf, ppaConf)
	write(t, root, "/etc/nginx/sites-available/a", "server { listen 80 default_server; }\n")
	write(t, root, "/usr/sbin/nginx", "")
	write(t, root, sourcesDir+"/ondrej-ubuntu-nginx-jammy.list", ppaList)
	write(t, root, sourcesDir+"/ubuntu.sources", "Types: deb\n")
	write(t, root, "/usr/share/nginx/modules-available/mod-http-geoip.conf", "load_module modules/ngx_http_geoip_module.so;\n")
	write(t, root, "/usr/share/nginx/modules-available/mod-stream.conf", "load_module modules/ngx_stream_module.so;\n")
	for _, l := range []struct{ name, target string }{
		{"/etc/nginx/sites-enabled/a", "../sites-available/a"},
		{modulesEnabled + "/50-mod-http-geoip.conf", "/usr/share/nginx/modules-available/mod-http-geoip.conf"},
		{modulesEnabled + "/50-mod-stream.conf", "/usr/share/nginx/modules-available/mod-stream.conf"},
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l.name)), 0o755); err != nil {
			t.Fatal(err)
		}
		target := l.target
		if strings.HasPrefix(target, "/") {
			target = filepath.Join(root, target)
		}
		if err := os.Symlink(target, filepath.Join(root, l.name)); err != nil {
			t.Fatal(err)
		}
	}
	fake := &runner.Fake{Default: &runner.Response{}, Responses: map[string]runner.Response{
		dpkgNginx: {Stdout: ppaVersion},
		"/usr/bin/apt-get -s -o Dpkg::Options::=--force-confold install --only-upgrade nginx": {Stdout: aptSim},
	}}
	out := &bytes.Buffer{}
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	return &Env{Runner: fake, Root: root, Out: out, Now: func() time.Time { now = now.Add(time.Second); return now }}, fake, out
}

func exists(root, p string) bool {
	_, err := os.Lstat(filepath.Join(root, p))
	return err == nil
}

func TestSourcePlanRefusals(t *testing.T) {
	ctx := context.Background()
	e, _, _ := ppaHost(t, "20.04")
	if p, _ := e.SourcePlanFor(ctx); !strings.Contains(p.Refusal, "too old") {
		t.Errorf("20.04: %q", p.Refusal)
	}
	e, fake, _ := ppaHost(t, "22.04")
	fake.Responses[dpkgNginx] = runner.Response{Stdout: "1.24.0-2ubuntu7.5"}
	if p, _ := e.SourcePlanFor(ctx); !strings.Contains(p.Refusal, "isn't the ondrej/nginx PPA's build") {
		t.Errorf("distro nginx: %q", p.Refusal)
	}
	if err := e.MoveToNginxOrg(ctx); err == nil || !strings.HasPrefix(err.Error(), "refused") {
		t.Errorf("move: %v", err)
	}
}

func TestSourcePlan(t *testing.T) {
	e, _, _ := ppaHost(t, "22.04")
	p, err := e.SourcePlanFor(context.Background())
	if err != nil || p.Refusal != "" {
		t.Fatalf("%v %q", err, p.Refusal)
	}
	if !reflect.DeepEqual(p.RemoveSources, []string{sourcesDir + "/ondrej-ubuntu-nginx-jammy.list"}) {
		t.Errorf("sources: %v", p.RemoveSources)
	}
	if p.SourceLine != "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/mainline/ubuntu jammy nginx" {
		t.Errorf("source line: %s", p.SourceLine)
	}
	if len(p.LoadModules) != 3 || !reflect.DeepEqual(p.RemoveLinks, []string{modulesEnabled + "/50-mod-http-geoip.conf"}) {
		t.Errorf("modules: %+v links %v", p.LoadModules, p.RemoveLinks)
	}
}

func TestMoveToNginxOrg(t *testing.T) {
	e, fake, out := ppaHost(t, "22.04")
	fake.Queue = map[string][]runner.Response{dpkgNginx: {{Stdout: ppaVersion}, {Stdout: orgVersion}, {Stdout: orgVersion}}}
	if err := e.MoveToNginxOrg(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := []string{
		dpkgNginx, "/usr/sbin/nginx -t", "/usr/sbin/nginx -t",
		"/usr/bin/apt-get -q -o Dir::Etc::sourcelist=sources.list.d/nginx.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update",
		"/usr/bin/apt-get -s -o Dpkg::Options::=--force-confold install --only-upgrade nginx",
		"/usr/bin/apt-get -q -y -o Dpkg::Options::=--force-confold install --only-upgrade nginx",
		"/usr/sbin/nginx -t", "/usr/bin/systemctl restart nginx", dpkgNginx, dpkgNginx,
	}
	if got := fake.Argvs(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands:\n%s", strings.Join(got, "\n"))
	}
	if exists(e.Root, sourcesDir+"/ondrej-ubuntu-nginx-jammy.list") || !exists(e.Root, sourcesDir+"/ubuntu.sources") {
		t.Error("sources not swapped")
	}
	if !bytes.Equal([]byte(read(t, e.Root, keyringPath)), nginxOrgKeyring) || read(t, e.Root, pinPath) != pinContent {
		t.Error("keyring or pin wrong")
	}
	if got := read(t, e.Root, mainConf); strings.Contains(got, "brotli") || !strings.Contains(got, "include /etc/nginx/modules-enabled") {
		t.Errorf("nginx.conf:\n%s", got)
	}
	if exists(e.Root, modulesEnabled+"/50-mod-http-geoip.conf") || !exists(e.Root, modulesEnabled+"/50-mod-stream.conf") {
		t.Error("modules-enabled links wrong")
	}
	if !strings.Contains(out.String(), "and remove the PPA's libnginx-mod-http-geoip") {
		t.Errorf("output:\n%s", out)
	}

	// The rollback puts the apt files back, but not the configuration:
	// nginx.org's nginx can't load the PPA's modules.
	out.Reset()
	fake.Queue = nil
	fake.Responses[dpkgNginx] = runner.Response{Stdout: orgVersion}
	if err := e.RestoreSource(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read(t, e.Root, sourcesDir+"/ondrej-ubuntu-nginx-jammy.list") != ppaList || exists(e.Root, keyringPath) || exists(e.Root, nginxListPath) || exists(e.Root, pinPath) {
		t.Error("apt files not put back")
	}
	if strings.Contains(read(t, e.Root, mainConf), "brotli") || !strings.Contains(out.String(), "can't be reinstalled") {
		t.Errorf("config restored onto nginx.org's build, or no explanation:\n%s", out)
	}
	out.Reset()
	if err := e.RestoreSource(context.Background()); err != nil || !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("second restore: %v %s", err, out)
	}
}

func TestMovePutsEverythingBackWhenTheConfigNeedsAModule(t *testing.T) {
	e, fake, _ := ppaHost(t, "22.04")
	fake.Queue = map[string][]runner.Response{"/usr/sbin/nginx -t": {{}, {ExitCode: 1, Stderr: `nginx: [emerg] unknown directive "geoip_country"`}}}
	err := e.MoveToNginxOrg(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the PPA's nginx is still installed") {
		t.Fatalf("got %v", err)
	}
	if read(t, e.Root, mainConf) != ppaConf || read(t, e.Root, sourcesDir+"/ondrej-ubuntu-nginx-jammy.list") != ppaList || !exists(e.Root, modulesEnabled+"/50-mod-http-geoip.conf") || exists(e.Root, pinPath) {
		t.Error("not everything was put back")
	}
	for _, c := range fake.Argvs() {
		if strings.Contains(c, "apt-get") {
			t.Errorf("ran %s", c)
		}
	}
	if p, _ := e.SourcePlanFor(context.Background()); len(p.Restorable) != 0 {
		t.Errorf("restorable after a put-back: %v", p.Restorable)
	}
}

func TestRestoreSourceWhileThePPABuildIsInstalled(t *testing.T) {
	e, fake, _ := ppaHost(t, "22.04")
	fake.Queue = map[string][]runner.Response{"/usr/bin/apt-get -q -y -o Dpkg::Options::=--force-confold install --only-upgrade nginx": {{ExitCode: 100, Stderr: "E: Sub-process /usr/bin/dpkg returned an error code (1)"}}}
	if err := e.MoveToNginxOrg(context.Background()); err == nil || !strings.Contains(err.Error(), "dpkg --audit") {
		t.Fatalf("got %v", err)
	}
	if err := e.RestoreSource(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read(t, e.Root, mainConf) != ppaConf || !exists(e.Root, modulesEnabled+"/50-mod-http-geoip.conf") || exists(e.Root, pinPath) {
		t.Error("the PPA build's configuration wasn't put back")
	}
}

func TestSimulated(t *testing.T) {
	to, removed := simulated(aptSim)
	if to != orgVersion || !reflect.DeepEqual(removed, []string{"libnginx-mod-http-geoip"}) {
		t.Errorf("%s %v", to, removed)
	}
}
