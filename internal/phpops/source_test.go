package phpops

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
	dpkgAll       = "/usr/bin/dpkg-query -W -f ${db:Status-Abbrev}\t${Package}\t${Version}\n"
	dpkgRepo      = "/usr/bin/dpkg-query -W -f ${db:Status-Abbrev} debsuryorg-repository-php"
	dpkgKeyring   = "/usr/bin/dpkg-query -W -f ${db:Status-Abbrev} debsuryorg-archive-keyring"
	simRepo       = "/usr/bin/apt-get -s install debsuryorg-repository-php"
	installRepo   = "/usr/bin/apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install debsuryorg-repository-php"
	purgeRepo     = "/usr/bin/apt-get -q -y purge debsuryorg-repository-php"
	policyCommon  = "/usr/bin/apt-cache policy php-common"
	ppaFile       = aptSourcesDir + "/ondrej-ubuntu-php-noble.sources"
	ppaContent    = "Types: deb\nURIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu/\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/ondrej.gpg\n"
	suryContent   = "Types: deb\nURIs: https://packages.sury.org/php/\nSuites: noble\nComponents: main\nSigned-By: /usr/share/keyrings/debsuryorg-archive-keyring.gpg\n"
	ppaPHPVersion = "8.3.14-1+ubuntu24.04.1+deb.sury.org+1"
	policyOut     = `php-common:
  Installed: 2:96+ubuntu24.04.1+deb.sury.org+1
  Candidate: 2:97+ubuntu24.04.1+deb.sury.org+1
  Version table:
     2:97+ubuntu24.04.1+deb.sury.org+1 500
        500 https://packages.sury.org/php noble/main amd64 Packages
 *** 2:96+ubuntu24.04.1+deb.sury.org+1 100
        100 /var/lib/dpkg/status
`
)

// sourceRunner is runner.Fake plus what installing the repository package
// does to the files: its postinst writes php.sources.
type sourceRunner struct {
	*runner.Fake
	root string
}

func (r sourceRunner) Run(ctx context.Context, c runner.Command) (int, error) {
	code, err := r.Fake.Run(ctx, c)
	if strings.Join(c.Argv, " ") == installRepo && err == nil && code == 0 {
		if err := os.WriteFile(filepath.Join(r.root, surySourceFile), []byte(suryContent), 0o644); err != nil {
			return -1, err
		}
	}
	return code, err
}

func writeFile(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func present(root, p string) bool {
	_, err := os.Lstat(filepath.Join(root, p))
	return err == nil
}

// ppaPHPHost is Ubuntu 24.04 with PHP from the ondrej/php PPA and the
// repository package not installed.
func ppaPHPHost(t *testing.T) (*Env, *runner.Fake, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n")
	writeFile(t, root, aptSourcesDir+"/ubuntu.sources", "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\n")
	writeFile(t, root, ppaFile, ppaContent)
	fake := &runner.Fake{Default: &runner.Response{}, Responses: map[string]runner.Response{
		dpkgAll:      {Stdout: "ii \tphp8.3-cli\t" + ppaPHPVersion + "\nii \tphp-common\t2:96+ubuntu24.04.1+deb.sury.org+1\nii \tcurl\t8.5.0-2ubuntu10.6\nrc \tphp8.1-cli\t8.1.2-1+deb.sury.org+1\n"},
		dpkgRepo:     {ExitCode: 1, Stderr: "dpkg-query: no packages found matching debsuryorg-repository-php"},
		dpkgKeyring:  {ExitCode: 1},
		simRepo:      {Stdout: "Inst debsuryorg-archive-keyring (2025.11.18 LP-PPA-ondrej-php:24.04/noble [all])\nInst debsuryorg-repository-php (1.2 LP-PPA-ondrej-php:24.04/noble [all])\n"},
		policyCommon: {Stdout: policyOut},
	}}
	out := &bytes.Buffer{}
	now := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	return &Env{Runner: sourceRunner{fake, root}, Root: root, Out: out, Now: func() time.Time { now = now.Add(time.Second); return now }}, fake, out
}

func TestPHPSourcePlanRefusals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, want string
		setup      func(root string)
	}{
		{"not ubuntu", "isn't Ubuntu", func(root string) {
			writeFile(t, root, "/etc/os-release", "ID=debian\nVERSION_CODENAME=bookworm\n")
		}},
		{"no PPA", "nothing to move: the ondrej/php PPA isn't enabled", func(root string) {
			os.Remove(filepath.Join(root, ppaFile))
		}},
		{"already moved", "packages.sury.org/php already is (" + surySourceFile + ")", func(root string) {
			os.Remove(filepath.Join(root, ppaFile))
			writeFile(t, root, surySourceFile, suryContent)
		}},
		{"PPA in sources.list", "edit it by hand", func(root string) {
			writeFile(t, root, aptSourcesList, "deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main\n")
		}},
	} {
		e, fake, _ := ppaPHPHost(t)
		c.setup(e.Root)
		if p, err := e.SourcePlanFor(ctx); err != nil || !strings.Contains(p.Refusal, c.want) {
			t.Errorf("%s: %v %q", c.name, err, p.Refusal)
		}
		if err := e.MoveToSury(ctx); err == nil || !strings.HasPrefix(err.Error(), "refused") {
			t.Errorf("%s: move: %v", c.name, err)
		}
		for _, a := range fake.Argvs() {
			if strings.HasPrefix(a, aptGet) {
				t.Errorf("%s: ran %s", c.name, a)
			}
		}
	}
}

func TestPHPSourcePlanFindsThePPAAndItsMirror(t *testing.T) {
	e, _, _ := ppaPHPHost(t)
	writeFile(t, e.Root, aptSourcesDir+"/ondrej-ubuntu-php-noble.list", "deb [signed-by=/etc/apt/keyrings/ondrej.gpg] https://ppa.launchpad.net/ondrej/php/ubuntu noble main\n")
	writeFile(t, e.Root, aptSourcesDir+"/setup-php.sources", "Types: deb\nURIs: https://ppa.setup-php.com/ondrej/php/ubuntu\nSuites: noble\nComponents: main\n")
	writeFile(t, e.Root, aptSourcesDir+"/old.list", "# deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main\n")
	writeFile(t, e.Root, aptSourcesDir+"/off.sources", "Enabled: no\nTypes: deb\nURIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu/\nSuites: noble\n")
	writeFile(t, e.Root, aptSourcesDir+"/ondrej-ubuntu-php-noble.list.save", "deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main\n")
	writeFile(t, e.Root, aptSourcesDir+"/phpmyadmin.list", "deb https://ppa.launchpadcontent.net/ondrej/phpmyadmin/ubuntu noble main\n")
	p, err := e.SourcePlanFor(context.Background())
	if err != nil || p.Refusal != "" {
		t.Fatalf("%v %q", err, p.Refusal)
	}
	want := []string{aptSourcesDir + "/ondrej-ubuntu-php-noble.list", ppaFile, aptSourcesDir + "/setup-php.sources"}
	if !reflect.DeepEqual(p.PPASources, want) {
		t.Errorf("ppa sources: %v", p.PPASources)
	}
	if p.SuryEnabled || len(p.SurySources) != 0 || p.PHPPackages != 2 || p.probe != "php-common" || p.SourceFile != surySourceFile {
		t.Errorf("plan: %+v", p)
	}
}

func TestMoveToSuryThenRestore(t *testing.T) {
	e, fake, out := ppaPHPHost(t)
	ctx := context.Background()
	if err := e.MoveToSury(ctx); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := []string{
		dpkgAll, dpkgRepo, dpkgKeyring,
		"/usr/bin/apt-get -q -o Dir::Etc::sourcelist=" + ppaFile + " -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o Acquire::AllowReleaseInfoChange::Label=true update",
		simRepo, installRepo,
		"/usr/bin/apt-get -q -o Dir::Etc::sourcelist=" + surySourceFile + " -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update",
		policyCommon,
	}
	if got := fake.Argvs(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands:\n%s", strings.Join(got, "\n"))
	}
	if present(e.Root, ppaFile) || readFile(t, e.Root, surySourceFile) != suryContent || !present(e.Root, aptSourcesDir+"/ubuntu.sources") {
		t.Error("sources not swapped")
	}
	if !strings.Contains(out.String(), "candidate for php-common is 2:97+ubuntu24.04.1+deb.sury.org+1 from packages.sury.org/php") {
		t.Errorf("output:\n%s", out)
	}

	// The rollback puts the PPA back and purges the package the move
	// installed.
	fake.Calls = nil
	fake.Responses[dpkgRepo] = runner.Response{Stdout: "ii "}
	if err := e.RestoreSource(ctx); err != nil {
		t.Fatal(err)
	}
	if readFile(t, e.Root, ppaFile) != ppaContent || present(e.Root, surySourceFile) {
		t.Error("files not put back")
	}
	if got := fake.Argvs(); !reflect.DeepEqual(got, []string{dpkgRepo, purgeRepo}) {
		t.Errorf("restore commands: %v", got)
	}
	out.Reset()
	if err := e.RestoreSource(ctx); err != nil || !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("second restore: %v %s", err, out)
	}
}

func TestMoveToSuryPutsEverythingBackWhenTheInstallFails(t *testing.T) {
	e, fake, _ := ppaPHPHost(t)
	fake.Responses[installRepo] = runner.Response{ExitCode: 100, Stderr: "E: Sub-process /usr/bin/dpkg returned an error code (1)"}
	err := e.MoveToSury(context.Background())
	if err == nil || !strings.Contains(err.Error(), "every file was put back") {
		t.Fatalf("got %v", err)
	}
	if readFile(t, e.Root, ppaFile) != ppaContent || present(e.Root, surySourceFile) || present(e.Root, suryPrefFile) {
		t.Error("not everything was put back")
	}
	if got := fake.Argvs(); got[len(got)-1] != purgeRepo {
		t.Errorf("didn't purge the half-installed package: %v", got)
	}
	if p, _ := e.SourcePlanFor(context.Background()); len(p.Restorable) != 0 {
		t.Errorf("restorable after a put-back: %v", p.Restorable)
	}
}

func TestRestoreKeepsARepositoryPackageThatWasThere(t *testing.T) {
	e, fake, _ := ppaPHPHost(t)
	fake.Responses[dpkgRepo] = runner.Response{Stdout: "ii "}
	writeFile(t, e.Root, suryPrefFile, "Package: *\nPin: release o=LP-PPA-ondrej-php\nPin-Priority: 100\n")
	if err := e.MoveToSury(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.Calls = nil
	if err := e.RestoreSource(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.Argvs() {
		if strings.Contains(c, "purge") {
			t.Errorf("ran %s", c)
		}
	}
	if readFile(t, e.Root, ppaFile) != ppaContent || !present(e.Root, suryPrefFile) || present(e.Root, surySourceFile) {
		t.Error("files not put back as they were")
	}
}
