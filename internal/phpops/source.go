package phpops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/filebackup"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

const (
	sourceBackupRoot  = "/var/backups/php-source"
	aptSourcesDir     = "/etc/apt/sources.list.d"
	aptSourcesList    = "/etc/apt/sources.list"
	surySourceFile    = "/etc/apt/sources.list.d/php.sources"
	suryPrefFile      = "/etc/apt/preferences.d/php.pref"
	repositoryPackage = "debsuryorg-repository-php"
	keyringPackage    = "debsuryorg-archive-keyring"
	aptGet            = "/usr/bin/apt-get"
)

var (
	// ppaPHPSource is the ondrej/php PPA, on Launchpad or its setup-php
	// mirror.
	ppaPHPSource  = regexp.MustCompile(`(ppa\.launchpad(content)?\.net|ppa\.setup-php\.com)/ondrej/php(/|\s|$)`)
	suryPHPSource = regexp.MustCompile(`packages\.sury\.org/php(/|\s|$)`)
	// suryCodenames are the Ubuntu releases packages.sury.org/php serves.
	suryCodenames = map[string]bool{"jammy": true, "noble": true, "resolute": true}
	// sourceAptEnv keeps dpkg and ucf from asking anything.
	sourceAptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "UCF_FORCE_CONFFOLD=1"}
)

// SourcePlan is what moving PHP from the ondrej/php PPA to
// packages.sury.org would change. The php_source state tool and the dry
// run report it.
type SourcePlan struct {
	OS          string   `json:"os"`
	Codename    string   `json:"codename"`
	Refusal     string   `json:"refusal"`
	PPASources  []string `json:"ppa_sources"`
	SuryEnabled bool     `json:"sury_enabled"`
	SurySources []string `json:"sury_sources"`
	PHPPackages int      `json:"php_packages"`
	SourceFile  string   `json:"source_file"`
	Steps       []string `json:"steps"`
	Restorable  []string `json:"restorable"`
	// probe is an installed PPA-built package whose candidate shows which
	// repository apt now takes PHP from.
	probe string
}

type sourceManifest struct {
	Created             string             `json:"created"`
	RepositoryInstalled bool               `json:"repository_installed"`
	KeyringInstalled    bool               `json:"keyring_installed"`
	Entries             []filebackup.Entry `json:"entries"`
}

// SourcePlanFor works out the move without changing anything.
func (e *Env) SourcePlanFor(ctx context.Context) (*SourcePlan, error) {
	p := &SourcePlan{SourceFile: surySourceFile, Restorable: []string{}}
	osr, _ := os.ReadFile(e.path("/etc/os-release"))
	rel := state.ParseOSRelease(string(osr))
	p.OS, p.Codename = rel["PRETTY_NAME"], rel["VERSION_CODENAME"]

	var inMain bool
	p.PPASources, p.SurySources, inMain = e.scanSources()
	p.SuryEnabled = len(p.SurySources) > 0

	// Only Ubuntu has dpkg to ask; anywhere else the plan just refuses.
	var ppaBuilt []string
	if rel["ID"] == "ubuntu" {
		var err error
		if ppaBuilt, err = e.ppaBuiltPackages(ctx); err != nil {
			return nil, err
		}
	}
	p.PHPPackages = len(ppaBuilt)
	for _, name := range ppaBuilt {
		if name == "php-common" {
			p.probe = name
		}
	}
	if p.probe == "" && len(ppaBuilt) > 0 {
		p.probe = ppaBuilt[0]
	}

	switch {
	case rel["ID"] != "ubuntu":
		p.Refusal = "this host isn't Ubuntu; the ondrej/php PPA is only for Ubuntu"
	case !suryCodenames[p.Codename]:
		p.Refusal = fmt.Sprintf("packages.sury.org/php has no packages for Ubuntu %q: it serves jammy, noble and resolute", p.Codename)
	case inMain:
		p.Refusal = aptSourcesList + " itself enables the ondrej/php PPA; edit it by hand"
	case len(p.PPASources) == 0 && p.SuryEnabled:
		p.Refusal = "nothing to move: the ondrej/php PPA isn't enabled, and packages.sury.org/php already is (" + strings.Join(p.SurySources, ", ") + ")"
	case len(p.PPASources) == 0:
		p.Refusal = "nothing to move: the ondrej/php PPA isn't enabled"
	case contains(p.PPASources, surySourceFile):
		p.Refusal = surySourceFile + " enables the ondrej/php PPA; edit it by hand"
	}

	backups, err := filebackup.Unrestored[sourceManifest](e.Root, sourceBackupRoot)
	if err != nil {
		return nil, err
	}
	for _, b := range backups {
		p.Restorable = append(p.Restorable, filepath.Base(b.Dir))
	}
	check := "check apt-cache policy picks packages.sury.org/php's list"
	if p.probe != "" {
		check = "check apt-cache policy " + p.probe + " has a candidate from packages.sury.org/php"
	}
	p.Steps = []string{
		"Back up the PPA's source files, " + surySourceFile + " and " + suryPrefFile + " to " + sourceBackupRoot,
		"apt-get update for the PPA's source files only, accepting their Label change to \"PPA for PHP (deprecated)\"; nothing else may change",
		"apt-get install " + repositoryPackage + " from the PPA (with " + keyringPackage + "): it writes " + surySourceFile + " for packages.sury.org/php and pins the PPA below it",
		"Check packages.sury.org/php is enabled, then remove the PPA's source files",
		"apt-get update for packages.sury.org/php's source only, then " + check,
		"No PHP package is installed, upgraded or removed and no service is restarted: the installed PHP packages stay and take their next updates from packages.sury.org/php",
	}
	return p, nil
}

// scanSources lists the apt source files that enable the ondrej/php PPA
// and packages.sury.org/php, and whether sources.list itself enables the
// PPA. apt reads only .list and .sources files in sources.list.d.
func (e *Env) scanSources() (ppa, sury []string, inMain bool) {
	ppa, sury = []string{}, []string{}
	if b, err := os.ReadFile(e.path(aptSourcesList)); err == nil {
		inMain = enables(b, false, ppaPHPSource)
		if enables(b, false, suryPHPSource) {
			sury = append(sury, aptSourcesList)
		}
	}
	entries, _ := os.ReadDir(e.path(aptSourcesDir))
	for _, ent := range entries {
		deb822 := strings.HasSuffix(ent.Name(), ".sources")
		if ent.IsDir() || (!deb822 && !strings.HasSuffix(ent.Name(), ".list")) {
			continue
		}
		full := filepath.Join(aptSourcesDir, ent.Name())
		b, err := os.ReadFile(e.path(full))
		if err != nil {
			continue
		}
		if enables(b, deb822, ppaPHPSource) {
			ppa = append(ppa, full)
		}
		if enables(b, deb822, suryPHPSource) {
			sury = append(sury, full)
		}
	}
	return ppa, sury, inMain
}

// enables reports whether an apt source file has an enabled entry whose
// line matches re: one-line style (.list) or deb822 (.sources).
func enables(b []byte, deb822 bool, re *regexp.Regexp) bool {
	if !deb822 {
		for _, line := range strings.Split(string(b), "\n") {
			line, _, _ = strings.Cut(line, "#")
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "deb") && re.MatchString(line) {
				return true
			}
		}
		return false
	}
	for _, stanza := range regexp.MustCompile(`\n\s*\n`).Split(string(b), -1) {
		matched, disabled := false, false
		for _, line := range strings.Split(stanza, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "#") {
				continue
			}
			if k, v, ok := strings.Cut(t, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Enabled") && strings.EqualFold(strings.TrimSpace(v), "no") {
				disabled = true
			}
			matched = matched || re.MatchString(t)
		}
		if matched && !disabled {
			return true
		}
	}
	return false
}

// ppaBuiltPackages lists the installed packages built by Ondřej Surý (their
// version has deb.sury.org or debsuryorg), sorted.
func (e *Env) ppaBuiltPackages(ctx context.Context) ([]string, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("dpkg-query exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || len(f[0]) < 2 || f[0][1] != 'i' {
			continue
		}
		if strings.Contains(f[2], "deb.sury.org") || strings.Contains(f[2], "debsuryorg") {
			names = append(names, f[1])
		}
	}
	sort.Strings(names)
	return names, nil
}

// isInstalled reports whether dpkg has the package installed.
func (e *Env) isInstalled(ctx context.Context, name string) bool {
	out, _, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}", name)
	return err == nil && code == 0 && len(out) >= 2 && out[1] == 'i'
}

// aptQuiet runs an apt command, keeping its output for the error.
func (e *Env) aptQuiet(ctx context.Context, what string, argv ...string) (string, error) {
	out, stderr, code, err := e.run(ctx, sourceAptEnv, argv...)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if code != 0 {
		return "", fmt.Errorf("%s failed with status %d:\n%s", what, code, tail(stderr+out))
	}
	return out, nil
}

// refreshOnly runs apt-get update for one source file, leaving every other
// list alone.
func refreshOnly(file string, extra ...string) []string {
	argv := []string{aptGet, "-q", "-o", "Dir::Etc::sourcelist=" + file, "-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0"}
	return append(append(argv, extra...), "update")
}

// MoveToSury moves PHP's apt source from the deprecated ondrej/php PPA to
// packages.sury.org/php, the way the PPA's own notice says: install
// debsuryorg-repository-php from the PPA, then remove the PPA. It installs,
// upgrades or removes no PHP package. Any failure puts every file back and
// purges debsuryorg-repository-php if this installed it.
func (e *Env) MoveToSury(ctx context.Context) error {
	p, err := e.SourcePlanFor(ctx)
	if err != nil {
		return err
	}
	if p.Refusal != "" {
		return errors.New("refused: " + p.Refusal)
	}
	m := sourceManifest{
		Created:             e.Now().UTC().Format(time.RFC3339),
		RepositoryInstalled: e.isInstalled(ctx, repositoryPackage),
		KeyringInstalled:    e.isInstalled(ctx, keyringPackage),
	}
	dir, err := filebackup.NewDir(e.Root, sourceBackupRoot, e.Now())
	if err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	for i, path := range append(append([]string{}, p.PPASources...), surySourceFile, suryPrefFile) {
		en, err := filebackup.Save(e.Root, dir, strconv.Itoa(i), path, "apt")
		if err != nil {
			return fmt.Errorf("backup failed, nothing was changed: %w", err)
		}
		m.Entries = append(m.Entries, en)
	}
	if err := filebackup.WriteManifest(dir, m); err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	e.say("Backed up %d path(s) to %s", len(m.Entries), dir)

	installTried, removed := false, false
	putBack := func(cause error) error {
		var errs []error
		if installTried && !m.RepositoryInstalled {
			if _, err := e.aptQuiet(ctx, "purging "+repositoryPackage, aptGet, "-q", "-y", "purge", repositoryPackage); err != nil {
				errs = append(errs, err)
			} else {
				e.say("Purged %s, which this had installed (%s stays installed)", repositoryPackage, keyringPackage)
			}
		}
		if err := filebackup.Restore(e.Root, m.Entries, dir, nil); err != nil {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w; putting things back failed too (backup in %s): %v", cause, dir, err)
		}
		_ = filebackup.MarkRestored(dir, e.Now(), "put back after a failure")
		if removed {
			return fmt.Errorf("%w; the PPA's source files were put back after they had been removed, and no PHP package was changed (backup in %s)", cause, dir)
		}
		return fmt.Errorf("%w; every file was put back and no PHP package was changed (backup in %s)", cause, dir)
	}

	// 1. The PPA's lists, accepting only its new Label.
	for _, f := range p.PPASources {
		if _, err := e.aptQuiet(ctx, "updating "+f, refreshOnly(f, "-o", "Acquire::AllowReleaseInfoChange::Label=true")...); err != nil {
			return putBack(err)
		}
		e.say("Updated %s's package list, accepting its new Label", f)
	}

	// 2. debsuryorg-repository-php, checked first so it can't touch PHP.
	sim, err := e.aptQuiet(ctx, "simulating the install of "+repositoryPackage, aptGet, "-s", "install", repositoryPackage)
	if err != nil {
		return putBack(err)
	}
	gone, added := simulatedChanges(sim)
	if len(gone) > 0 {
		return putBack(fmt.Errorf("installing %s would remove %s", repositoryPackage, strings.Join(gone, ", ")))
	}
	for _, n := range added {
		if strings.Contains(n, "php") && n != repositoryPackage {
			return putBack(fmt.Errorf("installing %s would also install or upgrade %s", repositoryPackage, n))
		}
	}
	installTried = true
	argv := append([]string{aptGet, "-q", "-y"}, aptOptions...)
	if _, err := e.aptQuiet(ctx, "installing "+repositoryPackage, append(argv, "install", repositoryPackage)...); err != nil {
		return putBack(err)
	}
	e.say("Installed %s (%s)", repositoryPackage, strings.Join(added, ", "))

	// 3. packages.sury.org/php must be enabled before the PPA goes.
	_, surySources, _ := e.scanSources()
	if len(surySources) == 0 {
		return putBack(fmt.Errorf("%s didn't enable packages.sury.org/php: no %s", repositoryPackage, surySourceFile))
	}
	e.say("packages.sury.org/php is enabled in %s", strings.Join(surySources, ", "))
	for _, f := range p.PPASources {
		if err := os.Remove(e.path(f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return putBack(err)
		}
		removed = true
		e.say("Removed %s", f)
	}

	// 4. packages.sury.org/php's lists, and apt now takes PHP from there.
	for _, f := range surySources {
		if _, err := e.aptQuiet(ctx, "updating "+f, refreshOnly(f)...); err != nil {
			return putBack(err)
		}
		e.say("Updated %s's package list", f)
	}
	if p.probe != "" {
		policy, err := e.aptQuiet(ctx, "apt-cache policy "+p.probe, "/usr/bin/apt-cache", "policy", p.probe)
		if err != nil {
			return putBack(err)
		}
		candidate, ok := candidateFrom(policy, suryPHPSource)
		if !ok {
			return putBack(fmt.Errorf("apt's candidate for %s (%q) doesn't come from packages.sury.org/php", p.probe, candidate))
		}
		e.say("apt's candidate for %s is %s from packages.sury.org/php", p.probe, candidate)
	} else {
		list := fmt.Sprintf("/var/lib/apt/lists/packages.sury.org_php_dists_%s_InRelease", p.Codename)
		if _, err := os.Stat(e.path(list)); err != nil {
			return putBack(fmt.Errorf("packages.sury.org/php's list didn't download: no %s", list))
		}
	}
	e.say("Done: the ondrej/php PPA's sources are removed and apt takes PHP from packages.sury.org/php. The %d installed package(s) built by Ondřej Surý stay as they are and get their next updates from there; no PHP package was installed, upgraded or removed and no service was restarted. Backup: %s", p.PHPPackages, dir)
	return nil
}

// candidateFrom reads `apt-cache policy` for one package: its candidate,
// and whether one of the candidate's sources matches re.
func candidateFrom(policy string, re *regexp.Regexp) (string, bool) {
	candidate, inTable, atCandidate := "", false, false
	for _, line := range strings.Split(policy, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Candidate:"):
			candidate = strings.TrimSpace(strings.TrimPrefix(t, "Candidate:"))
			continue
		case strings.HasPrefix(t, "Version table:"):
			inTable = true
			continue
		case !inTable || t == "":
			continue
		}
		f := strings.Fields(strings.TrimPrefix(t, "*** "))
		_, numeric := strconv.Atoi(f[0])
		if len(f) >= 2 && numeric == nil && (strings.Contains(f[1], "://") || strings.HasPrefix(f[1], "/")) {
			if atCandidate && re.MatchString(t) {
				return candidate, true
			}
			continue
		}
		atCandidate = f[0] == candidate
	}
	return candidate, false
}

// RestoreSource is the rollback of MoveToSury: it puts back the PPA's
// source files, php.sources and php.pref from the newest backup, and
// purges debsuryorg-repository-php if the move installed it.
func (e *Env) RestoreSource(ctx context.Context) error {
	backups, err := filebackup.Unrestored[sourceManifest](e.Root, sourceBackupRoot)
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		e.say("No move to packages.sury.org to put back: nothing to do")
		return nil
	}
	b := backups[0]
	if err := filebackup.Restore(e.Root, b.M.Entries, b.Dir, nil); err != nil {
		return err
	}
	e.say("Put back the apt source files from %s", b.Dir)
	if !b.M.RepositoryInstalled && e.isInstalled(ctx, repositoryPackage) {
		if _, err := e.aptQuiet(ctx, "purging "+repositoryPackage, aptGet, "-q", "-y", "purge", repositoryPackage); err != nil {
			return err
		}
		e.say("Purged %s, which the move had installed; %s stays installed", repositoryPackage, keyringPackage)
	}
	e.say("Installed PHP packages were left as they are. The ondrej/php PPA is frozen and deprecated: it gets no more updates, and while apt holds its old package list, apt-get update fails on its changed Label until that is accepted (-o Acquire::AllowReleaseInfoChange::Label=true).")
	return filebackup.MarkRestored(b.Dir, e.Now(), "")
}
