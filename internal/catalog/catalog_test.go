package catalog

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedCatalog(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"agent.upgrade@1",
		"collector.upgrade@1",
		"package.hold@1", "package.install@1", "package.refresh@1", "package.unhold@1", "package.upgrade@1",
		"packages.upgrade@1",
		"service.disable@1", "service.enable@1", "service.reload@1", "service.restart@1", "service.start@1", "service.stop@1",
		"system.reboot@1",
	}
	if got := c.Keys(); !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	tiers := map[string]Tier{
		"package.hold@1": TierLow, "package.install@1": TierMedium, "package.refresh@1": TierLow,
		"package.unhold@1": TierLow, "package.upgrade@1": TierMedium, "packages.upgrade@1": TierMedium,
		"service.disable@1": TierMedium, "service.enable@1": TierLow,
		"service.reload@1": TierLow, "service.restart@1": TierLow,
		"service.start@1": TierLow, "service.stop@1": TierMedium,
		"system.reboot@1": TierHigh, "agent.upgrade@1": TierHigh, "collector.upgrade@1": TierHigh,
	}
	for _, d := range c.Definitions() {
		if d.MinTier != tiers[d.Key()] {
			t.Errorf("%s min_tier = %s, want %s", d.Key(), d.MinTier, tiers[d.Key()])
		}
		if d.Reboots != (d.Key() == "system.reboot@1") {
			t.Errorf("%s reboots = %v", d.Key(), d.Reboots)
		}
	}
}

func TestExpand(t *testing.T) {
	c := MustEmbedded()
	up, _ := c.Get("package.upgrade", 1)
	params := map[string]any{"name": "openssl", "to": "3.0.13-0ubuntu3.4"}
	got, err := up.Expand(PackageManagerApt, params)
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"/usr/bin/apt-get", "-q", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "install", "--only-upgrade", "openssl=3.0.13-0ubuntu3.4"}
	if !reflect.DeepEqual(got.Argv, wantArgv) {
		t.Fatalf("argv = %q", got.Argv)
	}
	if !reflect.DeepEqual(got.Env, []string{"DEBIAN_FRONTEND=noninteractive"}) || !got.Privileged {
		t.Fatalf("env = %q privileged = %v", got.Env, got.Privileged)
	}
	dnf, err := up.Expand(PackageManagerDnf, map[string]any{"name": "openssl", "to": "1:3.0.7-27.el9"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dnf.Argv, " ") != "/usr/bin/dnf -y upgrade openssl-1:3.0.7-27.el9" {
		t.Fatalf("dnf argv = %q", dnf.Argv)
	}
	dry, err := up.ExpandDryRun(PackageManagerApt, params)
	if err != nil || dry.Privileged || dry.Argv[1] != "-s" {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	h, err := up.HealthArgs(params)
	if err != nil || h["name"] != "openssl" || h["version"] != "3.0.13-0ubuntu3.4" {
		t.Fatalf("health args = %v, %v", h, err)
	}

	restart, _ := c.Get("service.restart", 1)
	r, err := restart.Expand(PackageManagerDnf, map[string]any{"unit": "nginx.service"})
	if err != nil || strings.Join(r.Argv, " ") != "/usr/bin/systemctl restart nginx.service" {
		t.Fatalf("restart = %+v, %v", r, err)
	}
}

func TestExpandRefusesOptionLikeValues(t *testing.T) {
	restart, _ := MustEmbedded().Get("service.restart", 1)
	for _, v := range []any{"--now", "", true} {
		if _, err := restart.Expand(PackageManagerApt, map[string]any{"unit": v}); err == nil {
			t.Errorf("Expand(%v) succeeded", v)
		}
	}
	if _, err := restart.Expand(PackageManagerApt, map[string]any{}); err == nil {
		t.Error("Expand with missing param succeeded")
	}
}

func TestEmbeddedParamPatterns(t *testing.T) {
	c := MustEmbedded()
	cases := []struct {
		op     string
		params string
		ok     bool
	}{
		{"package.upgrade", `{"name":"openssl","to":"3.0.13-0ubuntu3.4"}`, true},
		{"package.upgrade", `{"name":"libstdc++6","to":"1:14.2.0-4ubuntu2~24.04"}`, true},
		{"package.upgrade", `{"name":"openssl","to":"3.0.13","x":"1"}`, false},
		{"package.upgrade", `{"name":"-openssl","to":"3.0.13"}`, false},
		{"package.upgrade", `{"name":"openssl;id","to":"3.0.13"}`, false},
		{"package.upgrade", `{"name":"openssl","to":"3 0"}`, false},
		{"package.upgrade", `{"name":"openssl","to":"-1"}`, false},
		{"package.upgrade", `{"name":"openssl"}`, false},
		{"package.install", `{"name":"openssl","version":"3.0.13-0ubuntu3.1"}`, true},
		{"service.restart", `{"unit":"nginx.service"}`, true},
		{"service.restart", `{"unit":"getty@tty1.service"}`, true},
		{"service.restart", `{"unit":"nginx"}`, false},
		{"service.restart", `{"unit":"nginx.socket"}`, false},
		{"service.restart", `{"unit":"-x.service"}`, false},
		{"service.restart", `{"unit":"a b.service"}`, false},
		{"service.restart", `{"unit":"../x.service"}`, false},
		{"service.stop", `{"unit":"nginx.service\n"}`, false},
	}
	for _, tc := range cases {
		d, _ := c.Get(tc.op, 1)
		var v any
		if err := json.Unmarshal([]byte(tc.params), &v); err != nil {
			t.Fatal(err)
		}
		err := d.Params.Validate(v)
		if (err == nil) != tc.ok {
			t.Errorf("%s %s: err = %v, want ok=%v", tc.op, tc.params, err, tc.ok)
		}
	}
}

const validDef = `{
  "name": "test.op", "version": 1, "description": "d", "min_tier": "low",
  "params": {"type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string","pattern":"^[a-z]+$","maxLength":5}}},
  "rollback": null, "irreversible": false, "health_check": "h", "files_written": [],
  "agent": {
    "privileged": true,
    "argv": {"apt": ["/bin/x", "{a}"], "dnf": ["/bin/x", "{a}"]},
    "sudo": {"apt": "/bin/x *", "dnf": "/bin/x *"},
    "health": {"check": "service_state", "args": {"unit": "{a}", "state": "active"}}
  }
}`

func TestParseRejects(t *testing.T) {
	if _, err := Parse([]byte(validDef)); err != nil {
		t.Fatalf("valid definition rejected: %v", err)
	}
	cases := map[string][2]string{
		"unknown field":         {`"files_written": []`, `"files_written": [], "extra": 1`},
		"bad tier":              {`"min_tier": "low"`, `"min_tier": "trivial"`},
		"open params":           {`"additionalProperties":false,`, ``},
		"unknown schema kw":     {`"maxLength":5`, `"maxLength":5,"format":"x"`},
		"unanchored pattern":    {`"^[a-z]+$"`, `"[a-z]+"`},
		"no maxLength":          {`,"maxLength":5`, ``},
		"relative argv0":        {`"apt": ["/bin/x", "{a}"]`, `"apt": ["x", "{a}"]`},
		"undeclared param":      {`"apt": ["/bin/x", "{a}"]`, `"apt": ["/bin/x", "{b}"]`},
		"malformed placeholder": {`"apt": ["/bin/x", "{a}"]`, `"apt": ["/bin/x", "{a"]`},
		"missing dnf":           {`, "dnf": ["/bin/x", "{a}"]}`, `}`},
		"wrong sudo":            {`"apt": "/bin/x *"`, `"apt": "/bin/x"`},
		"unknown health":        {`"check": "service_state"`, `"check": "ping"`},
		"health args":           {`"state": "active"`, `"other": "x"`},
		"irreversible rollback": {`"rollback": null, "irreversible": false`, `"rollback": "test.op", "irreversible": true`},
		"bad name":              {`"name": "test.op"`, `"name": "Test"`},
		"unknown pm":            {`"dnf": ["/bin/x", "{a}"]}`, `"dnf": ["/bin/x", "{a}"], "zypper": ["/bin/x"]}`},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(validDef, edit[0], edit[1], 1)
			if doc == validDef {
				t.Fatalf("edit %q did not apply", edit[0])
			}
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("Parse succeeded, want error")
			}
		})
	}
}

func TestLoadChecksFileNameAndRollback(t *testing.T) {
	if _, err := Load(fstest.MapFS{"test.op@2.json": {Data: []byte(validDef)}}); err == nil {
		t.Error("mismatched file name accepted")
	}
	bad := strings.Replace(validDef, `"rollback": null`, `"rollback": "test.missing"`, 1)
	if _, err := Load(fstest.MapFS{"test.op@1.json": {Data: []byte(bad)}}); err == nil {
		t.Error("unknown rollback accepted")
	}
	if _, err := Load(fstest.MapFS{"test.op@1.json": {Data: []byte(validDef)}}); err != nil {
		t.Errorf("valid catalog rejected: %v", err)
	}
}

func TestExport(t *testing.T) {
	out, err := MustEmbedded().Export("0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "argv") || strings.Contains(string(out), "sudo") {
		t.Fatal("export leaks agent-only fields")
	}
	var doc struct {
		CatalogVersion string           `json:"catalog_version"`
		Operations     []map[string]any `json:"operations"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.CatalogVersion != "0.1.0" || len(doc.Operations) != 15 {
		t.Fatalf("doc = %+v", doc)
	}
	wantKeys := []string{"description", "dry_run", "files_written", "health_check", "irreversible", "min_tier", "name", "params", "rollback", "version"}
	for _, op := range doc.Operations {
		var keys []string
		for k := range op {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if op["name"] == "system.reboot" {
			// reboots is only exported when true.
			if op["reboots"] != true {
				t.Fatalf("system.reboot = %v", op)
			}
			keys = slicesDelete(keys, "reboots")
		}
		if op["name"] == "agent.upgrade" {
			if op["restarts_agent"] != true {
				t.Fatalf("agent.upgrade = %v", op)
			}
			keys = slicesDelete(keys, "restarts_agent")
		}
		if !reflect.DeepEqual(keys, wantKeys) {
			t.Fatalf("op keys = %v", keys)
		}
		if op["name"] == "package.upgrade" {
			if op["rollback"] != "package.install" || op["dry_run"] != true || op["min_tier"] != "medium" {
				t.Fatalf("package.upgrade = %v", op)
			}
		}
		if op["name"] == "service.restart" && (op["rollback"] != nil || op["dry_run"] != false) {
			t.Fatalf("service.restart = %v", op)
		}
	}
}

// The committed example must match what the binary prints.
func TestSudoersExampleUpToDate(t *testing.T) {
	want, err := os.ReadFile("../../deploy/sudoers.example")
	if err != nil {
		t.Fatal(err)
	}
	got := MustEmbedded().Sudoers("bifrost")
	if got != string(want) {
		t.Fatalf("deploy/sudoers.example is stale; run `make sudoers`.\n%s", got)
	}
	if !strings.Contains(got, `Dpkg\:\:Options\:\:\=--force-confold`) {
		t.Fatal("sudoers special characters not escaped")
	}
	if strings.Count(got, "/usr/bin/systemctl restart *") != 1 {
		t.Fatal("shared service rule should be listed once")
	}
}

func TestTier(t *testing.T) {
	for _, name := range []string{"low", "medium", "high", "critical"} {
		tier, err := ParseTier(name)
		if err != nil || tier.String() != name {
			t.Errorf("ParseTier(%q) = %v, %v", name, tier, err)
		}
	}
	if _, err := ParseTier("none"); err == nil {
		t.Error("ParseTier(none) succeeded")
	}
}

func slicesDelete(list []string, item string) []string {
	out := []string{}
	for _, v := range list {
		if v != item {
			out = append(out, v)
		}
	}
	return out
}

func TestExpandList(t *testing.T) {
	c := MustEmbedded()
	up, _ := c.Get("packages.upgrade", 1)
	params := map[string]any{"packages": []any{
		map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.4"},
		map[string]any{"name": "libssl3t64", "version": "3.0.13-0ubuntu3.4"},
	}}
	if err := up.Params.Validate(params); err != nil {
		t.Fatal(err)
	}
	apt, err := up.Expand(PackageManagerApt, params)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(apt.Argv[len(apt.Argv)-3:], " "); got != "--only-upgrade openssl=3.0.13-0ubuntu3.4 libssl3t64=3.0.13-0ubuntu3.4" {
		t.Fatalf("apt argv tail = %q", got)
	}
	dnf, err := up.Expand(PackageManagerDnf, params)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dnf.Argv, " "); got != "/usr/bin/dnf -y upgrade openssl-3.0.13-0ubuntu3.4 libssl3t64-3.0.13-0ubuntu3.4" {
		t.Fatalf("dnf argv = %q", got)
	}
	// The sudo rule is the single-package rule: no new sudo surface.
	single, _ := c.Get("package.upgrade", 1)
	if up.Sudo[PackageManagerApt] != single.Sudo[PackageManagerApt] || up.Sudo[PackageManagerDnf] != single.Sudo[PackageManagerDnf] {
		t.Fatalf("sudo = %v, want %v", up.Sudo, single.Sudo)
	}
	list, err := up.HealthList(params)
	if err != nil || len(list) != 2 || list[1] != (NameVersion{"libssl3t64", "3.0.13-0ubuntu3.4"}) {
		t.Fatalf("health list = %v, %v", list, err)
	}
	if err := up.Params.Validate(map[string]any{"packages": []any{}}); err == nil {
		t.Fatal("empty package list accepted")
	}
	bad := map[string]any{"packages": []any{map[string]any{"name": "-oAPT::x", "version": "1"}}}
	if err := up.Params.Validate(bad); err == nil {
		t.Fatal("option-like package name accepted")
	}
	if _, err := up.Expand(PackageManagerApt, map[string]any{"packages": []any{}}); err == nil {
		t.Fatal("expanded an empty list")
	}
}

func TestListArgumentRules(t *testing.T) {
	list := `{"type":"object","additionalProperties":false,"required":["pkgs"],"properties":{"pkgs":{"type":"array","minItems":1,"maxItems":5,
		"items":{"type":"object","additionalProperties":false,"required":["name","version"],"properties":{
		"name":{"type":"string","pattern":"^[a-z]+$","maxLength":10},"version":{"type":"string","pattern":"^[0-9.]+$","maxLength":10}}}}}}`
	def := func(params, argv, health string) string {
		return `{"name":"test.op","version":1,"description":"d","min_tier":"low","params":` + params + `,"rollback":null,"irreversible":false,
			"health_check":"h","files_written":[],"agent":{"privileged":false,"argv":{"apt":` + argv + `,"dnf":` + argv + `},"health":` + health + `}}`
	}
	okHealth := `{"check":"package_versions","args":{"packages":"{pkgs}"}}`
	if _, err := Parse([]byte(def(list, `["/bin/x","{*pkgs:{name}={version}}"]`, okHealth))); err != nil {
		t.Fatalf("valid list definition rejected: %v", err)
	}
	cases := map[string]string{
		"not last":        def(list, `["/bin/x","{*pkgs:{name}}","y"]`, okHealth),
		"unknown field":   def(list, `["/bin/x","{*pkgs:{nope}}"]`, okHealth),
		"no placeholder":  def(list, `["/bin/x","{*pkgs:literal}"]`, okHealth),
		"not a list":      def(list, `["/bin/x","{*name:{name}}"]`, okHealth),
		"list as string":  def(list, `["/bin/x","{pkgs}"]`, okHealth),
		"unbounded":       def(strings.Replace(list, `"maxItems":5,`, ``, 1), `["/bin/x","{*pkgs:{name}}"]`, okHealth),
		"may be empty":    def(strings.Replace(list, `"minItems":1,`, `"minItems":0,`, 1), `["/bin/x","{*pkgs:{name}}"]`, okHealth),
		"health not list": def(list, `["/bin/x","{*pkgs:{name}}"]`, `{"check":"package_versions","args":{"packages":"x{pkgs}"}}`),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	reboot := `{"name":"test.op","version":1,"description":"d","min_tier":"high","params":{"type":"object","additionalProperties":false,"properties":{}},
		"rollback":"test.op","irreversible":false,"reboots":true,"health_check":"h","files_written":[],
		"agent":{"privileged":false,"argv":{"apt":["/bin/x"],"dnf":["/bin/x"]},"health":{"check":"reboot_scheduled","args":{}}}}`
	if _, err := Parse([]byte(reboot)); err == nil {
		t.Error("a rebooting operation with a rollback was accepted")
	}
}

func TestSudoersStateTools(t *testing.T) {
	got := MustEmbedded().Sudoers("bifrost")
	for _, want := range []string{
		"bifrost ALL=(root) NOPASSWD: /usr/sbin/needrestart -b -r l\n",
		"bifrost ALL=(root) NOPASSWD: /usr/bin/dnf -q needs-restarting -s\n",
		"bifrost ALL=(root) NOPASSWD: /usr/sbin/shutdown -r +1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sudoers lacks %q", want)
		}
	}
}
