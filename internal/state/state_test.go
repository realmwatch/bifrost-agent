package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/redact"
	"github.com/realmwatch/bifrost-agent/internal/runner"
)

const dpkgFixture = "openssl\t3.0.13-0ubuntu3.1\tamd64\tii \n" +
	"libssl3t64\t3.0.13-0ubuntu3.1\tamd64\tii \n" +
	"oldpkg\t1.0\tall\trc \n" +
	"broken line\n"

const rpmFixture = "openssl\t1:3.0.7-27.el9\tx86_64\n" +
	"bash\t5.1.8-9.el9\tx86_64\n" +
	"gpg-pubkey\t8483c65d-5ccc5b19\t(none)\n"

const aptListFixture = `Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
curl/noble-updates 8.5.0-2ubuntu10.5 amd64 [upgradable from: 8.5.0-2ubuntu10.4]
`

const dnfCheckFixture = `
openssl.x86_64                     1:3.0.7-28.el9_4                 baseos
bash.x86_64                        5.1.8-9.el9_4                    baseos
Obsoleting Packages
grub2-tools.x86_64                 1:2.06-80.el9                    baseos
`

const dnfSecurityFixture = `RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64
RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64
`

const systemctlFixture = `Id=nginx.service
ActiveState=active
SubState=running
LoadState=loaded
UnitFileState=enabled
ActiveEnterTimestamp=Thu 2026-10-01 12:00:00 UTC
`

const journalFixture = `2026-10-31T09:00:00+0000 web-01 app[123]: started
2026-10-31T09:00:01+0000 web-01 app[123]: connecting with password=hunter2
2026-10-31T09:00:02+0000 web-01 app[123]: Authorization: Bearer abc
`

const mountsFixture = `/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda2 /srv/my\040data xfs rw 0 0
/dev/sda1 / ext4 rw 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
`

const meminfoFixture = `MemTotal:        2000000 kB
MemFree:          500000 kB
MemAvailable:    1500000 kB
SwapTotal:       1000000 kB
SwapFree:         900000 kB
`

const ssFixture = `tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=812,fd=6),("nginx",pid=811,fd=6))
tcp   LISTEN 0      4096            [::]:22           [::]:*    users:(("sshd",pid=700,fd=4))
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128                *:9100            *:*
`

const whoFixture = `alex     pts/0        2026-10-31 09:12 (192.0.2.10)
root     tty1         2026-10-30 18:00
`

func TestParsers(t *testing.T) {
	if got := ParseDpkgQuery(dpkgFixture); !reflect.DeepEqual(got, []Package{
		{"openssl", "3.0.13-0ubuntu3.1", "amd64"}, {"libssl3t64", "3.0.13-0ubuntu3.1", "amd64"},
	}) {
		t.Errorf("dpkg = %v", got)
	}
	if got := ParseRpmQuery(rpmFixture); !reflect.DeepEqual(got, []Package{
		{"openssl", "1:3.0.7-27.el9", "x86_64"}, {"bash", "5.1.8-9.el9", "x86_64"},
	}) {
		t.Errorf("rpm = %v", got)
	}
	if got := ParseAptUpgradable(aptListFixture); !reflect.DeepEqual(got, []Update{
		{"openssl", "3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.4", true},
		{"curl", "8.5.0-2ubuntu10.4", "8.5.0-2ubuntu10.5", false},
	}) {
		t.Errorf("apt list = %v", got)
	}
	sec := ParseDnfSecurity(dnfSecurityFixture)
	if !sec["openssl"] || !sec["openssl-libs"] || len(sec) != 2 {
		t.Errorf("dnf security = %v", sec)
	}
	if got := ParseDnfCheckUpdate(dnfCheckFixture, map[string]string{"openssl": "1:3.0.7-27.el9"}, sec); !reflect.DeepEqual(got, []Update{
		{"openssl", "1:3.0.7-27.el9", "1:3.0.7-28.el9_4", true},
		{"bash", "", "5.1.8-9.el9_4", false},
	}) {
		t.Errorf("dnf check-update = %v", got)
	}
	if got := ParseSystemctlShow("nginx.service", systemctlFixture); got != (ServiceStatus{
		"nginx.service", "active", "running", "loaded", "enabled", "2026-10-01T12:00:00Z",
	}) {
		t.Errorf("systemctl = %+v", got)
	}
	if got := ParseSystemctlShow("x.service", "ActiveState=inactive\nActiveEnterTimestamp=\n"); got.Since != "" || got.ActiveState != "inactive" {
		t.Errorf("systemctl inactive = %+v", got)
	}
	j := ParseJournal(journalFixture + "-- No entries --\n")
	if len(j) != 3 || !strings.Contains(j[1], "password="+redact.Mask) || strings.Contains(j[2], "abc") {
		t.Errorf("journal = %q", j)
	}
	if got := ParseMounts(mountsFixture); !reflect.DeepEqual(got, []Mount{{Mount: "/", FS: "ext4"}, {Mount: "/srv/my data", FS: "xfs"}}) {
		t.Errorf("mounts = %+v", got)
	}
	mem, err := ParseMeminfo(meminfoFixture)
	if err != nil || mem != (Memory{2000000 * 1024, 1500000 * 1024, 1000000 * 1024, 900000 * 1024}) {
		t.Errorf("meminfo = %+v, %v", mem, err)
	}
	if _, err := ParseMeminfo("garbage"); err == nil {
		t.Error("meminfo garbage accepted")
	}
	if got := ParseSS(ssFixture); !reflect.DeepEqual(got, []Port{
		{"tcp", "::", 22, "sshd"}, {"tcp", "0.0.0.0", 80, "nginx"}, {"tcp", "*", 9100, ""}, {"udp", "127.0.0.53%lo", 53, ""},
	}) {
		t.Errorf("ss = %+v", got)
	}
	if got := ParseWho(whoFixture); !reflect.DeepEqual(got, []Session{
		{"alex", "pts/0", "192.0.2.10", "2026-10-31T09:12:00Z"}, {"root", "tty1", "", "2026-10-30T18:00:00Z"},
	}) {
		t.Errorf("who = %+v", got)
	}
}

func TestParseOSRelease(t *testing.T) {
	r := ParseOSRelease("# comment\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_ID='24.04'\n")
	if r["ID"] != "ubuntu" || r["PRETTY_NAME"] != "Ubuntu 24.04.1 LTS" || r["VERSION_ID"] != "24.04" {
		t.Fatalf("os-release = %v", r)
	}
}

func fixtureRoot(t *testing.T, osRelease string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":            osRelease,
		"etc/machine-id":            "0123456789abcdef0123456789abcdef\n",
		"proc/sys/kernel/osrelease": "6.8.0-45-generic\n",
		"proc/uptime":               "12345.67 5000.00\n",
		"proc/meminfo":              meminfoFixture,
		"proc/mounts":               mountsFixture,
	}
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func testEnv(t *testing.T, pm string, fake *runner.Fake) *Env {
	root := fixtureRoot(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	return &Env{
		Runner: fake, Root: root, PackageManager: pm,
		Hostname: func() (string, error) { return "web-01", nil },
		Statfs: func(string) (FSStat, error) {
			return FSStat{BlockSize: 4096, Blocks: 1000, BlocksFree: 400, BlocksAvail: 300}, nil
		},
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunTool(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		"dpkg-query -W -f ${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n": {Stdout: dpkgFixture},
		"apt list --upgradable": {Stdout: aptListFixture, Stderr: "WARNING: apt does not have a stable CLI interface."},
		"systemctl show nginx.service --no-pager -p Id -p ActiveState -p SubState -p LoadState -p UnitFileState -p ActiveEnterTimestamp": {Stdout: systemctlFixture},
		"journalctl -u nginx.service -n 20 -o short-iso --no-pager -q":                                                                   {Stdout: journalFixture},
		"journalctl -u nginx.service -n 100 -o short-iso --no-pager -q":                                                                  {Stdout: ""},
		"ss -tulnpH": {Stdout: ssFixture},
		"who":        {Stdout: whoFixture},
	}}
	e := testEnv(t, "apt", fake)
	ctx := context.Background()
	cases := []struct {
		tool    string
		args    string
		want    string // substring of the JSON result
		wantErr string
	}{
		{"os", `{}`, `"machine_id":"0123456789abcdef0123456789abcdef"`, ""},
		{"os", `{}`, `"uptime_seconds":12345`, ""},
		{"packages", `{}`, `"name":"libssl3t64"`, ""},
		{"packages", `{"names":["openssl"]}`, `[{"arch":"amd64","name":"openssl","version":"3.0.13-0ubuntu3.1"}]`, ""},
		{"packages", `{"names":["bad;name"]}`, "", "bad args"},
		{"pending_updates", `{}`, `"security":true`, ""},
		{"service_status", `{"unit":"nginx.service"}`, `"active_state":"active"`, ""},
		{"service_status", `{"unit":"nginx"}`, "", "bad args"},
		{"service_status", `{}`, "", "bad args"},
		{"journal", `{"unit":"nginx.service","lines":20}`, `password=[REDACTED]`, ""},
		{"journal", `{"unit":"nginx.service"}`, `{"lines":[]}`, ""},
		{"journal", `{"unit":"nginx.service","lines":501}`, "", "bad args"},
		{"journal", `{"unit":"--all.service"}`, "", "bad args"},
		{"disk", `{}`, `"size_bytes":4096000,"used_bytes":2457600`, ""},
		{"memory", `{}`, `"total_bytes":2048000000`, ""},
		{"ports", `{}`, `"process":"sshd"`, ""},
		{"sessions", `{}`, `"from":"192.0.2.10"`, ""},
		{"os", `{"x":1}`, "", "bad args"},
		{"nope", `{}`, "", "unknown tool"},
	}
	for _, tc := range cases {
		t.Run(tc.tool+tc.args, func(t *testing.T) {
			var args map[string]any
			dec := json.NewDecoder(strings.NewReader(tc.args))
			dec.UseNumber()
			if err := dec.Decode(&args); err != nil {
				t.Fatal(err)
			}
			res, err := e.RunTool(ctx, tc.tool, args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := asJSON(t, res); !strings.Contains(got, tc.want) {
				t.Fatalf("result %s does not contain %s", got, tc.want)
			}
		})
	}
	for _, c := range fake.Calls {
		if !reflect.DeepEqual(c.Env, []string{"TZ=UTC"}) {
			t.Errorf("%v ran with env %v", c.Argv, c.Env)
		}
	}
}

func TestDnfTools(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Response{
		"dnf -q check-update": {Stdout: dnfCheckFixture, ExitCode: 100},
		"rpm -qa --queryformat %{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n": {Stdout: rpmFixture},
		"dnf -q updateinfo list --security": {Stdout: dnfSecurityFixture},
	}}
	e := testEnv(t, "dnf", fake)
	res, err := e.RunTool(context.Background(), "pending_updates", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := asJSON(t, res); got != `[{"candidate":"1:3.0.7-28.el9_4","current":"1:3.0.7-27.el9","name":"openssl","security":true},{"candidate":"5.1.8-9.el9_4","current":"5.1.8-9.el9","name":"bash","security":false}]` {
		t.Fatalf("pending = %s", got)
	}
	fake.Responses["dnf -q check-update"] = runner.Response{ExitCode: 1}
	if _, err := e.RunTool(context.Background(), "pending_updates", nil); err == nil {
		t.Fatal("dnf failure not reported")
	}
}

func TestNoPackageManager(t *testing.T) {
	e := testEnv(t, "", &runner.Fake{})
	if _, err := e.RunTool(context.Background(), "packages", nil); err == nil {
		t.Fatal("want error without a package manager")
	}
}

func TestFactsAndDetect(t *testing.T) {
	e := testEnv(t, "apt", &runner.Fake{})
	f := e.Facts()
	want := Facts{Hostname: "web-01", OS: OSInfo{"ubuntu", "24.04", "Ubuntu 24.04.1 LTS"}, Kernel: "6.8.0-45-generic", UptimeSeconds: 12345, PackageManager: "apt"}
	if f != want {
		t.Fatalf("facts = %+v", f)
	}
	cases := map[string]string{
		"ID=ubuntu\n": "apt",
		"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n":  "apt",
		"ID=rocky\nID_LIKE=\"rhel centos fedora\"\n": "dnf",
		"ID=fedora\n": "dnf",
		"ID=arch\n":   "",
	}
	for osr, pm := range cases {
		e := &Env{Root: fixtureRoot(t, osr)}
		if got := e.DetectPackageManager(); got != pm {
			t.Errorf("DetectPackageManager(%q) = %q, want %q", osr, got, pm)
		}
	}
	if id, err := e.MachineID(); err != nil || id != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("machine id = %q, %v", id, err)
	}
}

func TestToolNames(t *testing.T) {
	want := []string{"disk", "journal", "memory", "os", "packages", "pending_updates", "ports", "service_status", "sessions"}
	if got := ToolNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("tools = %v", got)
	}
}
