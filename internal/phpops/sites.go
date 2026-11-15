package phpops

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/state"
)

// MaxSites caps the sites a report lists.
const MaxSites = 200

const maxServerNames = 50

var (
	socketRe   = regexp.MustCompile(`php([0-9]+\.[0-9]+)-fpm[A-Za-z0-9._-]*\.sock`)
	fpmPkgRe   = regexp.MustCompile(`^php([0-9]+\.[0-9]+)-fpm$`)
	phpPkgRe   = regexp.MustCompile(`^php([0-9]+\.[0-9]+)-(fpm|cli)$`)
	phpCallRe  = regexp.MustCompile(`(^|[\s;&|"'=(])((?:/usr(?:/local)?/bin/)?php)([0-9]+\.[0-9]+)?([\s;&|"')]|$)`)
	altPHPRe   = regexp.MustCompile(`^php([0-9]+\.[0-9]+)$`)
	serverName = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9.*-]*$`)
)

// SitesReport is what `php sites` prints, for the php_sites state tool.
type SitesReport struct {
	Versions  Versions `json:"versions"`
	Sites     []Site   `json:"sites"`
	Truncated bool     `json:"truncated"`
}

// Versions are the host's PHP versions.
type Versions struct {
	Installed   []string            `json:"installed"`
	FPM         map[string]FPMState `json:"fpm"`
	Installable []string            `json:"installable"`
	Alternative string              `json:"alternative"`
}

// FPMState is one version's FPM service.
type FPMState struct {
	Active  bool `json:"active"`
	Enabled bool `json:"enabled"`
}

// Site is one app an enabled nginx vhost serves with PHP.
type Site struct {
	Root        string   `json:"root"`
	ServerNames []string `json:"server_names"`
	Vhosts      []string `json:"vhosts"`
	PHP         string   `json:"php"`
	Repo        string   `json:"repo"`
	RequirePHP  string   `json:"require_php"`
	PlatformPHP string   `json:"platform_php"`
	CLI         []CLIUse `json:"cli"`
	Forge       bool     `json:"forge"`
	// LockPHP is each locked package's own PHP constraint, from
	// composer.lock (packages and packages-dev).
	LockPHP       []LockPHP `json:"lock_php"`
	LockTruncated bool      `json:"lock_truncated"`
}

// LockPHP is one locked package's require.php.
type LockPHP struct {
	Package    string `json:"package"`
	Constraint string `json:"constraint"`
}

// MaxLockPHP caps the lock constraints a site lists.
const MaxLockPHP = 500

// CLIUse is a cron, supervisor or systemd file that runs PHP for a site.
// PHP is the minor it names, or "php" for a bare php.
type CLIUse struct {
	Kind string `json:"kind"`
	File string `json:"file"`
	PHP  string `json:"php"`
}

// serverBlock is one nginx server block: lines are 0-based, inclusive.
type serverBlock struct {
	file        string // the enabled path, as listed
	real        string // the file it resolves to
	start, end  int
	names       []string
	appRoot     string
	php         string
	forgeMarker bool
}

// Sites reports the host's PHP versions and the sites nginx serves with
// PHP: each site's FPM version, repository, composer.json PHP constraints
// and the cron, supervisor and systemd files that run PHP for it.
func (e *Env) Sites(ctx context.Context) (*SitesReport, error) {
	if e.packageManager() != catalog.PackageManagerApt {
		return nil, errors.New("php_sites is only supported on apt hosts")
	}
	r := &SitesReport{Versions: Versions{Installed: []string{}, FPM: map[string]FPMState{}, Installable: []string{}}, Sites: []Site{}}

	installed, fpm, err := e.installedVersions(ctx)
	if err != nil {
		return nil, err
	}
	r.Versions.Installed = installed
	for _, v := range fpm {
		r.Versions.FPM[v] = FPMState{Active: e.unitIs(ctx, "is-active", "php"+v+"-fpm"), Enabled: e.unitIs(ctx, "is-enabled", "php"+v+"-fpm")}
	}
	if r.Versions.Installable, err = e.installable(ctx); err != nil {
		return nil, err
	}
	r.Versions.Alternative = e.alternative()

	blocks, err := e.serverBlocks()
	if err != nil {
		return nil, err
	}
	sites := map[string]*Site{}
	var order []string
	for _, b := range blocks {
		if b.appRoot == "" || b.php == "" && !b.forgeMarker {
			continue
		}
		s, ok := sites[b.appRoot]
		if !ok {
			s = &Site{Root: b.appRoot, ServerNames: []string{}, Vhosts: []string{}, CLI: []CLIUse{}, LockPHP: []LockPHP{}}
			sites[b.appRoot] = s
			order = append(order, b.appRoot)
		}
		if s.PHP == "" {
			s.PHP = b.php
		}
		s.Forge = s.Forge || b.forgeMarker
		if !contains(s.Vhosts, b.file) {
			s.Vhosts = append(s.Vhosts, b.file)
		}
		for _, n := range b.names {
			if !contains(s.ServerNames, n) && len(s.ServerNames) < maxServerNames {
				s.ServerNames = append(s.ServerNames, n)
			}
		}
	}
	sort.Strings(order)
	if len(order) > MaxSites {
		order, r.Truncated = order[:MaxSites], true
	}
	forgeHome := false
	if info, err := os.Stat(e.path("/home/forge")); err == nil && info.IsDir() {
		forgeHome = true
	}
	files := e.cliFiles()
	for _, root := range order {
		s := sites[root]
		s.Forge = s.Forge || forgeHome
		s.Repo = e.repo(root)
		s.RequirePHP, s.PlatformPHP = e.composerPHP(root)
		s.CLI = cliUses(files, root)
		s.LockPHP, s.LockTruncated = e.lockPHP(root)
		r.Sites = append(r.Sites, *s)
	}
	return r, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (e *Env) packageManager() string {
	return (&state.Env{Root: e.Root}).DetectPackageManager()
}

// installedVersions lists minors with an installed fpm or cli package, and
// those with fpm, both sorted.
func (e *Env) installedVersions(ctx context.Context) (installed, fpm []string, err error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n")
	if err != nil {
		return nil, nil, err
	}
	if code != 0 {
		return nil, nil, fmt.Errorf("dpkg-query exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	seen, seenFPM := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || len(f[0]) < 2 || f[0][1] != 'i' {
			continue
		}
		m := phpPkgRe.FindStringSubmatch(f[1])
		if m == nil {
			continue
		}
		seen[m[1]] = true
		if m[2] == "fpm" {
			seenFPM[m[1]] = true
		}
	}
	return sortVersions(seen), sortVersions(seenFPM), nil
}

// installable lists the minors whose FPM package apt has a candidate for.
func (e *Env) installable(ctx context.Context) ([]string, error) {
	out, stderr, code, err := e.run(ctx, nil, "/usr/bin/apt-cache", "pkgnames", "php")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("apt-cache pkgnames exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	var names []string
	for _, n := range strings.Fields(out) {
		if fpmPkgRe.MatchString(n) {
			names = append(names, n)
		}
	}
	found := map[string]bool{}
	if len(names) == 0 {
		return []string{}, nil
	}
	cands, err := e.candidates(ctx, names)
	if err != nil {
		return nil, err
	}
	for n := range cands {
		found[fpmPkgRe.FindStringSubmatch(n)[1]] = true
	}
	return sortVersions(found), nil
}

// candidates returns the packages among names that apt can install, with
// their candidate versions.
func (e *Env) candidates(ctx context.Context, names []string) (map[string]string, error) {
	out, stderr, code, err := e.run(ctx, nil, append([]string{"/usr/bin/apt-cache", "policy"}, names...)...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("apt-cache policy exited with status %d: %s", code, strings.TrimSpace(stderr))
	}
	return parsePolicy(out), nil
}

// parsePolicy reads `apt-cache policy` output into package → candidate,
// leaving out packages with no candidate.
func parsePolicy(out string) map[string]string {
	got := map[string]string{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && strings.HasSuffix(line, ":") {
			current = strings.TrimSuffix(line, ":")
			continue
		}
		t := strings.TrimSpace(line)
		if current != "" && strings.HasPrefix(t, "Candidate:") {
			c := strings.TrimSpace(strings.TrimPrefix(t, "Candidate:"))
			if c != "" && c != "(none)" {
				got[current] = c
			}
		}
	}
	return got
}

func sortVersions(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i], out[j]) })
	return out
}

func versionLess(a, b string) bool {
	am, an := splitVersion(a)
	bm, bn := splitVersion(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

func splitVersion(v string) (int, int) {
	a, b, _ := strings.Cut(v, ".")
	x, _ := strconv.Atoi(a)
	y, _ := strconv.Atoi(b)
	return x, y
}

func (e *Env) unitIs(ctx context.Context, verb, unit string) bool {
	_, _, code, err := e.run(ctx, nil, "/usr/bin/systemctl", verb, "--quiet", unit)
	return err == nil && code == 0
}

func (e *Env) alternative() string {
	target, err := os.Readlink(e.path("/etc/alternatives/php"))
	if err != nil {
		return ""
	}
	if m := altPHPRe.FindStringSubmatch(filepath.Base(target)); m != nil {
		return m[1]
	}
	return ""
}

// serverBlocks parses every enabled nginx vhost into its server blocks.
func (e *Env) serverBlocks() ([]serverBlock, error) {
	dir := e.path("/etc/nginx/sites-enabled")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading nginx sites: %w", err)
	}
	var out []serverBlock
	for _, entry := range entries {
		listed := filepath.Join(dir, entry.Name())
		real, err := filepath.EvalSymlinks(listed)
		if err != nil {
			continue // a dangling link serves nothing
		}
		info, err := os.Stat(real)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(real)
		if err != nil {
			return nil, err
		}
		for _, blk := range parseServerBlocks(string(b)) {
			blk.file = strings.TrimPrefix(listed, e.Root)
			blk.real = real
			out = append(out, blk)
		}
	}
	return out, nil
}

// parseServerBlocks finds top-level `server { ... }` blocks and what they
// say about the app: names, root (without /public), PHP socket, and
// whether Laravel Forge manages them.
func parseServerBlocks(text string) []serverBlock {
	var out []serverBlock
	lines := strings.Split(text, "\n")
	depth := 0
	var cur *serverBlock
	for i, raw := range lines {
		line := raw
		if c := strings.Index(line, "#"); c >= 0 {
			line = line[:c]
		}
		t := strings.TrimSpace(line)
		if cur == nil && depth == 0 && (strings.HasPrefix(t, "server{") || strings.HasPrefix(t, "server ") && strings.Contains(t, "{")) {
			cur = &serverBlock{start: i}
		}
		if cur != nil {
			if strings.Contains(raw, "forge-conf") || strings.Contains(raw, "FORGE CONFIG") {
				cur.forgeMarker = true
			}
			directive(t, cur)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if cur != nil && depth <= 0 {
			cur.end = i
			out = append(out, *cur)
			cur = nil
			depth = 0
		}
	}
	return out
}

func directive(t string, b *serverBlock) {
	for _, stmt := range strings.Split(t, ";") {
		if i := strings.LastIndexAny(stmt, "{}"); i >= 0 {
			stmt = stmt[i+1:] // what follows a block's opening or closing brace
		}
		f := strings.Fields(stmt)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "server_name":
			for _, n := range f[1:] {
				if n != "_" && serverName.MatchString(n) && !contains(b.names, n) {
					b.names = append(b.names, n)
				}
			}
		case "root":
			if b.appRoot == "" {
				root := filepath.Clean(strings.Trim(f[1], `"'`))
				if strings.HasPrefix(root, "/") {
					b.appRoot = strings.TrimSuffix(root, "/public")
				}
			}
		case "fastcgi_pass":
			if m := socketRe.FindStringSubmatch(f[1]); m != nil && b.php == "" {
				b.php = m[1]
			}
		}
	}
}

// repo is the site's origin remote as host/path, without credentials.
func (e *Env) repo(root string) string {
	f, err := os.Open(e.path(filepath.Join(root, ".git", "config")))
	if err != nil {
		return ""
	}
	defer f.Close()
	lines := bufio.NewScanner(f)
	inOrigin := false
	for lines.Scan() {
		t := strings.TrimSpace(lines.Text())
		if strings.HasPrefix(t, "[") {
			inOrigin = t == `[remote "origin"]`
			continue
		}
		if !inOrigin {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if ok && strings.TrimSpace(k) == "url" {
			return NormaliseRepo(strings.TrimSpace(v))
		}
	}
	return ""
}

// NormaliseRepo turns a git remote URL into host/path: no scheme, user,
// password, port or .git suffix. It returns "" for anything else.
func NormaliseRepo(u string) string {
	u = strings.TrimSpace(u)
	var host, path string
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		hostPart, p, ok := strings.Cut(rest, "/")
		if !ok {
			return ""
		}
		if at := strings.LastIndex(hostPart, "@"); at >= 0 {
			hostPart = hostPart[at+1:]
		}
		host, _, _ = strings.Cut(hostPart, ":")
		path = p
	} else if at := strings.Index(u, "@"); at >= 0 && strings.Contains(u[at:], ":") {
		h, p, _ := strings.Cut(u[at+1:], ":")
		host, path = h, p
	} else {
		return ""
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if host == "" || path == "" || !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(host) || !regexp.MustCompile(`^[A-Za-z0-9._~/-]+$`).MatchString(path) {
		return ""
	}
	return strings.ToLower(host) + "/" + path
}

// composerPHP reads composer.json's require.php and config.platform.php.
func (e *Env) composerPHP(root string) (require, platform string) {
	b, err := os.ReadFile(e.path(filepath.Join(root, "composer.json")))
	if err != nil {
		return "", ""
	}
	var c struct {
		Require map[string]any `json:"require"`
		Config  struct {
			Platform map[string]any `json:"platform"`
		} `json:"config"`
	}
	if json.Unmarshal(b, &c) != nil {
		return "", ""
	}
	if s, ok := c.Require["php"].(string); ok && len(s) <= 128 {
		require = s
	}
	if s, ok := c.Config.Platform["php"].(string); ok && len(s) <= 64 {
		platform = s
	}
	return require, platform
}

// cliFile is a cron, supervisor or systemd file's lines.
type cliFile struct {
	kind, path, real string
	lines            []string
}

func (e *Env) cliFiles() []cliFile {
	var out []cliFile
	for _, g := range []struct{ kind, glob string }{
		{"cron", "/etc/cron.d/*"},
		{"cron", "/var/spool/cron/crontabs/*"},
		{"supervisor", "/etc/supervisor/conf.d/*.conf"},
		{"systemd", "/etc/systemd/system/*.service"},
	} {
		paths, _ := filepath.Glob(e.path(g.glob))
		sort.Strings(paths)
		for _, p := range paths {
			info, err := os.Lstat(p)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			out = append(out, cliFile{kind: g.kind, path: strings.TrimPrefix(p, e.Root), real: p, lines: strings.Split(string(b), "\n")})
		}
	}
	return out
}

// mentionsRoot reports whether line names root as a whole path (not a
// longer one that starts with it, like root + ".old").
func mentionsRoot(line, root string) bool {
	for i := 0; ; {
		j := strings.Index(line[i:], root)
		if j < 0 {
			return false
		}
		end := i + j + len(root)
		if end == len(line) || strings.ContainsRune("/ \t\"';&|)", rune(line[end])) {
			return true
		}
		i = end
	}
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";")
}

func cliUses(files []cliFile, root string) []CLIUse {
	out := []CLIUse{}
	seen := map[string]bool{}
	for _, f := range files {
		for _, line := range f.lines {
			if isComment(line) || !mentionsRoot(line, root) {
				continue
			}
			for _, m := range phpCallRe.FindAllStringSubmatch(line, -1) {
				v := m[3]
				if v == "" {
					v = "php"
				}
				key := f.path + "\x00" + v
				if !seen[key] {
					seen[key] = true
					out = append(out, CLIUse{Kind: f.kind, File: f.path, PHP: v})
				}
			}
		}
	}
	return out
}

// lockPHP reads every locked package's own PHP constraint, deduped and
// capped at MaxLockPHP.
func (e *Env) lockPHP(root string) ([]LockPHP, bool) {
	out := []LockPHP{}
	f, err := os.Open(e.path(filepath.Join(root, "composer.lock")))
	if err != nil {
		return out, false
	}
	defer f.Close()
	var lock struct {
		Packages    []lockPackage `json:"packages"`
		PackagesDev []lockPackage `json:"packages-dev"`
	}
	if json.NewDecoder(io.LimitReader(f, 32<<20)).Decode(&lock) != nil {
		return out, false
	}
	seen := map[LockPHP]bool{}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		c, ok := p.Require["php"].(string)
		if !ok || p.Name == "" || len(p.Name) > 200 || len(c) > 200 {
			continue
		}
		entry := LockPHP{Package: p.Name, Constraint: c}
		if seen[entry] {
			continue
		}
		if len(out) == MaxLockPHP {
			return out, true
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return out, false
}

type lockPackage struct {
	Name    string         `json:"name"`
	Require map[string]any `json:"require"`
}
