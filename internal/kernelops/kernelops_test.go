package kernelops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/debversion"
	"github.com/realmwatch/bifrost-agent/internal/runner"
)

// host is a fake apt host: dpkg's package list changes as the purge runs.
type host struct {
	t        *testing.T
	root     string
	pkgs     map[string]pkg
	simExtra string
	simCode  int
	keep     string // a package the purge leaves behind
	calls    []string
	purged   []string
}

func newHost(t *testing.T, running string) *host {
	t.Helper()
	h := &host{t: t, root: t.TempDir(), pkgs: map[string]pkg{}}
	h.write("etc/os-release", "ID=ubuntu\n")
	h.write("proc/sys/kernel/osrelease", running+"\n")
	if err := os.MkdirAll(filepath.Join(h.root, "lib/modules", running), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"linux-generic", "linux-image-generic", "linux-headers-generic", "linux-firmware"} {
		h.add("ii", name, "6.8.0-49.49")
	}
	return h
}

// kernel installs the packages Ubuntu installs for a generic kernel.
func (h *host) kernel(release string) {
	abi := base(release)
	for _, name := range []string{"linux-image-" + release, "linux-modules-" + release, "linux-modules-extra-" + release, "linux-headers-" + release, "linux-headers-" + abi} {
		h.add("ii", name, abi+".1")
	}
}

func (h *host) add(status, name, version string) {
	h.pkgs[name] = pkg{Status: status, Name: name, Version: version}
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

func (h *host) env(out *strings.Builder) *Env { return &Env{Runner: h, Root: h.root, Out: out} }

func (h *host) Run(_ context.Context, c runner.Command) (int, error) {
	joined := strings.Join(c.Argv, " ")
	h.calls = append(h.calls, joined)
	out, code := "", 0
	switch {
	case c.Argv[0] == "/usr/bin/dpkg-query":
		names := make([]string, 0, len(h.pkgs))
		for n := range h.pkgs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := h.pkgs[n]
			out += fmt.Sprintf("%s \t%s\t%s\n", p.Status, p.Name, p.Version)
		}
	case strings.HasPrefix(joined, "/usr/bin/apt-get -s purge "):
		for _, n := range c.Argv[3:] {
			out += "Purg " + n + " [1]\n"
		}
		out += h.simExtra
		code = h.simCode
	case strings.HasPrefix(joined, "/usr/bin/apt-get -q -y "):
		for i, a := range c.Argv {
			if a == "purge" {
				for _, n := range c.Argv[i+1:] {
					if n != h.keep {
						delete(h.pkgs, n)
						h.purged = append(h.purged, n)
					}
				}
			}
		}
	default:
		h.t.Fatalf("unexpected command %q", joined)
	}
	if c.Stdout != nil {
		fmt.Fprint(c.Stdout, out)
	}
	return code, nil
}

func (h *host) ranPurge() bool {
	for _, c := range h.calls {
		if strings.HasPrefix(c, "/usr/bin/apt-get -q -y ") {
			return true
		}
	}
	return false
}

func TestRemovesOldKernelsAndKeepsTheRunningOne(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	for _, r := range []string{"6.8.0-41-generic", "6.8.0-45-generic", "6.8.0-49-generic"} {
		h.kernel(r)
	}
	var out strings.Builder

	if err := h.env(&out).Remove(context.Background(), []string{"6.8.0-45-generic", "6.8.0-41-generic", "6.8.0-45-generic"}); err != nil {
		t.Fatal(err)
	}

	sort.Strings(h.purged)
	want := []string{
		"linux-headers-6.8.0-41", "linux-headers-6.8.0-41-generic", "linux-headers-6.8.0-45", "linux-headers-6.8.0-45-generic",
		"linux-image-6.8.0-41-generic", "linux-image-6.8.0-45-generic",
		"linux-modules-6.8.0-41-generic", "linux-modules-6.8.0-45-generic", "linux-modules-extra-6.8.0-41-generic", "linux-modules-extra-6.8.0-45-generic",
	}
	if strings.Join(h.purged, " ") != strings.Join(want, " ") {
		t.Fatalf("purged %v, want %v", h.purged, want)
	}
	for _, keep := range []string{"linux-image-6.8.0-49-generic", "linux-headers-6.8.0-49", "linux-generic", "linux-image-generic"} {
		if _, ok := h.pkgs[keep]; !ok {
			t.Errorf("%s was removed", keep)
		}
	}
	for _, line := range []string{"Removed kernels 6.8.0-45-generic, 6.8.0-41-generic", "  linux-image-6.8.0-45-generic 6.8.0-45.1", "The running kernel 6.8.0-49-generic"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out.String())
		}
	}
}

func TestSkipsKernelsThatMustStayAndReportsThem(t *testing.T) {
	h := newHost(t, "6.8.0-45-generic")
	for _, r := range []string{"6.8.0-41-generic", "6.8.0-45-generic", "6.8.0-49-generic"} {
		h.kernel(r)
	}
	var out strings.Builder

	err := h.env(&out).Remove(context.Background(), []string{"6.8.0-41-generic", "6.8.0-45-generic", "6.8.0-49-generic", "6.8.0-30-generic"})
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range []string{
		"Skipped 6.8.0-45-generic: it's the running kernel",
		"Skipped 6.8.0-49-generic: newer than the running kernel 6.8.0-45-generic",
		"Skipped 6.8.0-30-generic: not installed",
	} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out.String())
		}
	}
	if _, ok := h.pkgs["linux-image-6.8.0-41-generic"]; ok {
		t.Error("the old kernel is still installed")
	}
	if _, ok := h.pkgs["linux-image-6.8.0-49-generic"]; !ok {
		t.Error("the newer kernel was removed")
	}
}

func TestRefusesWhenNothingCanGo(t *testing.T) {
	h := newHost(t, "6.8.0-45-generic")
	h.kernel("6.8.0-45-generic")
	var out strings.Builder

	err := h.env(&out).Remove(context.Background(), []string{"6.8.0-45-generic", "6.8.0-30-generic"})
	if err == nil || !strings.Contains(err.Error(), "none of the listed kernels can be removed") {
		t.Fatalf("got %v", err)
	}
	if h.ranPurge() {
		t.Error("purged anyway")
	}
}

func TestRefusesWhenThePurgeWouldTakeAMetapackage(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	h.kernel("6.8.0-45-generic")
	h.kernel("6.8.0-49-generic")
	h.simExtra = "Remv linux-generic [6.8.0-49.49]\nRemv linux-image-generic [6.8.0-49.49]\n"
	var out strings.Builder

	err := h.env(&out).Remove(context.Background(), []string{"6.8.0-45-generic"})
	if err == nil || !strings.Contains(err.Error(), "would also remove packages that must stay: linux-generic, linux-image-generic") {
		t.Fatalf("got %v", err)
	}
	if h.ranPurge() {
		t.Error("purged anyway")
	}
}

func TestRefusesWhenThePurgeWouldInstallSomething(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	h.kernel("6.8.0-45-generic")
	h.kernel("6.8.0-49-generic")
	h.simExtra = "Inst linux-image-6.8.0-50-generic (6.8.0-50.50 Ubuntu)\n"

	err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"6.8.0-45-generic"})
	if err == nil || !strings.Contains(err.Error(), "would also install: linux-image-6.8.0-50-generic") {
		t.Fatalf("got %v", err)
	}
	if h.ranPurge() {
		t.Error("purged anyway")
	}
}

func TestKeepsSharedHeadersAnotherFlavourStillUses(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	h.kernel("6.8.0-45-generic")
	h.kernel("6.8.0-49-generic")
	h.add("ii", "linux-image-6.8.0-45-lowlatency", "6.8.0-45.1")
	h.add("ii", "linux-headers-6.8.0-45-lowlatency", "6.8.0-45.1")

	if err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"6.8.0-45-generic"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.pkgs["linux-headers-6.8.0-45"]; !ok {
		t.Error("removed headers the lowlatency kernel still uses")
	}
	if _, ok := h.pkgs["linux-headers-6.8.0-45-generic"]; ok {
		t.Error("kept the generic kernel's own headers")
	}
}

func TestCloudFlavourSharedPackages(t *testing.T) {
	h := newHost(t, "7.0.0-1019-azure")
	for _, r := range []string{"7.0.0-1016-azure", "7.0.0-1019-azure"} {
		abi := base(r)
		for _, name := range []string{"linux-image-" + r, "linux-modules-" + r, "linux-headers-" + r, "linux-tools-" + r, "linux-cloud-tools-" + r,
			"linux-main-modules-zfs-" + r, "linux-azure-headers-" + abi, "linux-azure-tools-" + abi, "linux-azure-cloud-tools-" + abi, "linux-aws-7.0-headers-" + abi} {
			h.add("ii", name, "1")
		}
	}
	for _, name := range []string{"linux-azure", "linux-image-azure", "linux-tools-common", "linux-cloud-tools-common", "linux-base"} {
		h.add("ii", name, "1")
	}

	if err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"7.0.0-1016-azure"}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(h.purged)
	want := []string{
		"linux-aws-7.0-headers-7.0.0-1016", "linux-azure-cloud-tools-7.0.0-1016", "linux-azure-headers-7.0.0-1016", "linux-azure-tools-7.0.0-1016",
		"linux-cloud-tools-7.0.0-1016-azure", "linux-headers-7.0.0-1016-azure", "linux-image-7.0.0-1016-azure", "linux-main-modules-zfs-7.0.0-1016-azure",
		"linux-modules-7.0.0-1016-azure", "linux-tools-7.0.0-1016-azure",
	}
	if strings.Join(h.purged, " ") != strings.Join(want, " ") {
		t.Fatalf("purged %v,\nwant   %v", h.purged, want)
	}
}

func TestFailsWhenAPackageSurvivesThePurge(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	h.kernel("6.8.0-45-generic")
	h.kernel("6.8.0-49-generic")
	h.keep = "linux-modules-6.8.0-45-generic"

	err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"6.8.0-45-generic"})
	if err == nil || !strings.Contains(err.Error(), "still installed after the purge: linux-modules-6.8.0-45-generic") {
		t.Fatalf("got %v", err)
	}
}

func TestRefusesHeldAndBrokenPackages(t *testing.T) {
	for _, status := range []string{"hi", "iU"} {
		h := newHost(t, "6.8.0-49-generic")
		h.kernel("6.8.0-45-generic")
		h.kernel("6.8.0-49-generic")
		h.add(status, "linux-modules-6.8.0-45-generic", "1")

		err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"6.8.0-45-generic"})
		if err == nil || !strings.Contains(err.Error(), "refused: linux-modules-6.8.0-45-generic") {
			t.Fatalf("%s: got %v", status, err)
		}
		if h.ranPurge() {
			t.Errorf("%s: purged anyway", status)
		}
	}
}

func TestCheckSimulatesOnly(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	h.kernel("6.8.0-45-generic")
	h.kernel("6.8.0-49-generic")
	var out strings.Builder

	if err := h.env(&out).Check(context.Background(), []string{"6.8.0-45-generic"}); err != nil {
		t.Fatal(err)
	}
	if h.ranPurge() {
		t.Error("the check purged")
	}
	if !strings.Contains(out.String(), "Dry run: purging kernels 6.8.0-45-generic would remove only their packages: linux-headers-6.8.0-45") {
		t.Errorf("output: %s", out.String())
	}
}

func TestRejectsBadReleasesAndNonAptHosts(t *testing.T) {
	h := newHost(t, "6.8.0-49-generic")
	for _, bad := range [][]string{{"6.8.0-45-generic;reboot"}, {"-6.8"}, {"../../etc"}, {"6.8"}, {}, releases(MaxKernels + 1)} {
		if err := h.env(&strings.Builder{}).Remove(context.Background(), bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if len(h.calls) != 0 {
		t.Errorf("ran %v", h.calls)
	}

	h.write("etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")
	if err := h.env(&strings.Builder{}).Remove(context.Background(), []string{"6.8.0-45-generic"}); err == nil || !strings.Contains(err.Error(), "only supported on apt hosts") {
		t.Fatalf("got %v", err)
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"6.1.0-0.deb11.17-amd64", "6.1.0-18-amd64", "6.8.0-9-generic", "6.8.0-41-generic", "6.8.0-45-generic", "6.8.0-100-generic", "6.8.0-1012-aws", "6.10.0-1-generic"}
	for i := range ordered {
		for j := range ordered {
			want := min(max(i-j, -1), 1)
			if got := debversion.Compare(ordered[i], ordered[j]); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if debversion.Compare("1.0~rc1", "1.0") != -1 || debversion.Compare("1.0a", "1.0+") != -1 {
		t.Error("~ or letters sort wrong")
	}
}

// releases lists n distinct generic kernel releases, oldest first.
func releases(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("6.8.0-%d-generic", i+1)
	}
	return out
}

func TestRemovesFiftyKernelsInOnePurge(t *testing.T) {
	old := releases(MaxKernels)
	h := newHost(t, "6.8.0-200-generic")
	h.kernel("6.8.0-200-generic")
	for _, r := range old {
		h.kernel(r)
	}

	if err := h.env(&strings.Builder{}).Remove(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	purges := 0
	for _, c := range h.calls {
		if strings.HasPrefix(c, "/usr/bin/apt-get -q -y ") {
			purges++
		}
	}
	if purges != 1 || len(h.purged) != 5*MaxKernels {
		t.Fatalf("%d purge runs removed %d packages", purges, len(h.purged))
	}
	if _, ok := h.pkgs["linux-image-6.8.0-200-generic"]; !ok {
		t.Error("the running kernel was removed")
	}
}
