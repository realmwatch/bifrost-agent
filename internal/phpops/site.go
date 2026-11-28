package phpops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Retiring a site without deleting anything: site.disable takes it out of
// nginx, stops its workers and units and comments out its cron lines, and
// records each change so site.enable can put exactly that back.
const (
	// SiteHoldDir holds vhost files that were regular files in
	// sites-enabled or conf.d while their site is disabled. nginx never
	// includes it. It's 0755 and its files 0644, so Heimdall's collector,
	// running as an unprivileged user, can list the disabled sites.
	SiteHoldDir = "/etc/nginx/bifrost-disabled"
	// SiteRecordDir holds one restore record per disabled site.
	SiteRecordDir = "/var/lib/bifrost-agent/disabled-sites"
	// CronMarker starts each cron line site.disable commented out.
	CronMarker = "# bifrost site.disable: "
)

var (
	programNameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	unitNameRe      = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.service$`)
	programHeadRe   = regexp.MustCompile(`^\s*\[program:([^\]]+)\]\s*$`)
	sectionHeadRe   = regexp.MustCompile(`^\s*\[`)
	iniKeyRe        = regexp.MustCompile(`^\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$`)
	defaultServerRe = regexp.MustCompile(`(^|[\s;{])listen\s[^;]*\bdefault_server\b`)
	fcgiSocketRe    = regexp.MustCompile(`fastcgi_pass\s+unix:([^;\s]+)`)
	poolListenRe    = regexp.MustCompile(`^\s*listen\s*=\s*(\S+)\s*$`)
)

// SitePlan is what `site plan` prints, for the site_plan state tool: what
// site.disable or site.enable would change, or why it would refuse.
type SitePlan struct {
	Action  string `json:"action"`
	Root    string `json:"root"`
	Refusal string `json:"refusal"`
	// Disabled is true when a restore record says the site is disabled.
	Disabled   bool          `json:"disabled"`
	DisabledAt string        `json:"disabled_at,omitempty"`
	Vhosts     []PlanVhost   `json:"vhosts"`
	Supervisor []PlanProgram `json:"supervisor"`
	Cron       []PlanCron    `json:"cron"`
	Units      []PlanUnit    `json:"units"`
	// Pools are PHP-FPM pools only this site uses. They're left running.
	Pools []PlanPool `json:"fpm_pools"`
	// Drift is set when the record says the site is disabled but an
	// enabled vhost serves it again, for example after a hosting panel
	// rewrote its config.
	Drift []string `json:"drift"`
	Notes []string `json:"notes"`
}

// PlanVhost is one nginx file serving the site.
type PlanVhost struct {
	// Path is where nginx reads it: sites-enabled or conf.d.
	Path string `json:"path"`
	// Kind is "symlink" (removed, and linked again on enable) or "file"
	// (moved to SiteHoldDir and back).
	Kind        string   `json:"kind"`
	Target      string   `json:"target,omitempty"`
	HeldAt      string   `json:"held_at,omitempty"`
	ServerNames []string `json:"server_names"`
}

// PlanProgram is one supervisor program running under the root.
type PlanProgram struct {
	File    string `json:"file"`
	Program string `json:"program"`
	Running bool   `json:"running"`
}

// PlanCron is one cron line running under the root.
type PlanCron struct {
	File string `json:"file"`
	Line string `json:"line"`
}

// PlanUnit is one systemd service running under the root.
type PlanUnit struct {
	Unit    string `json:"unit"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

// PlanPool is a PHP-FPM pool only this site's vhosts use.
type PlanPool struct {
	File   string `json:"file"`
	Socket string `json:"socket"`
}

// siteRecord is the restore record: every change site.disable made, with
// what was there before.
type siteRecord struct {
	Root       string       `json:"root"`
	DisabledAt string       `json:"disabled_at"`
	Vhosts     []recVhost   `json:"vhosts"`
	Supervisor []recProgram `json:"supervisor"`
	Cron       []PlanCron   `json:"cron"`
	Units      []PlanUnit   `json:"units"`
}

type recVhost struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	HeldAt string `json:"held_at,omitempty"`
	// Mode is a held file's permissions before it was set to 0644, so
	// Heimdall's unprivileged collector can read it.
	Mode uint32 `json:"mode,omitempty"`
}

type recProgram struct {
	File    string `json:"file"`
	Program string `json:"program"`
	// Autostart is the program's autostart line before, "" if it had none.
	Autostart string `json:"autostart"`
	Running   bool   `json:"running"`
}

// vhostFile is one enabled nginx file and its server blocks.
type vhostFile struct {
	path, real, kind, target string
	lines                    []string
	blocks                   []serverBlock
}

func servesRoot(appRoot, root string) bool {
	return appRoot == root || strings.HasPrefix(appRoot, root+"/")
}

// enabledVhosts reads the files nginx loads sites from: everything in
// sites-enabled and conf.d/*.conf.
func (e *Env) enabledVhosts() ([]vhostFile, error) {
	var out []vhostFile
	for _, g := range []string{"/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"} {
		paths, err := filepath.Glob(e.path(g))
		if err != nil {
			return nil, err
		}
		sort.Strings(paths)
		for _, p := range paths {
			v, ok, err := e.readVhost(p)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (e *Env) readVhost(p string) (vhostFile, bool, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return vhostFile{}, false, nil
	}
	v := vhostFile{path: strings.TrimPrefix(p, e.Root), real: p, kind: "file"}
	if info.Mode()&fs.ModeSymlink != 0 {
		v.kind = "symlink"
		if v.target, err = os.Readlink(p); err != nil {
			return vhostFile{}, false, err
		}
		if v.real, err = filepath.EvalSymlinks(p); err != nil {
			return vhostFile{}, false, nil // a dangling link serves nothing
		}
	}
	if st, err := os.Stat(v.real); err != nil || !st.Mode().IsRegular() {
		return vhostFile{}, false, nil
	}
	b, err := os.ReadFile(v.real)
	if err != nil {
		return vhostFile{}, false, err
	}
	v.lines = strings.Split(string(b), "\n")
	v.blocks = parseServerBlocks(string(b))
	return v, true, nil
}

// split sorts a file's server blocks into the site's and other roots'.
func (v vhostFile) split(root string) (mine []serverBlock, others []string) {
	for _, b := range v.blocks {
		switch {
		case servesRoot(b.appRoot, root):
			mine = append(mine, b)
		case b.appRoot != "" && !contains(others, b.appRoot):
			others = append(others, b.appRoot)
		}
	}
	return mine, others
}

func (v vhostFile) defaultServer(blocks []serverBlock) bool {
	for _, b := range blocks {
		for i := b.start; i <= b.end && i < len(v.lines); i++ {
			line := v.lines[i]
			if c := strings.Index(line, "#"); c >= 0 {
				line = line[:c]
			}
			if defaultServerRe.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func (v vhostFile) sockets(blocks []serverBlock) []string {
	var out []string
	for _, b := range blocks {
		for i := b.start; i <= b.end && i < len(v.lines); i++ {
			if m := fcgiSocketRe.FindStringSubmatch(v.lines[i]); m != nil && !isComment(v.lines[i]) && !contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// program is one supervisor [program:x] section.
type program struct {
	name                 string
	start, end           int // header line, last line (inclusive)
	autostartLine        int // -1 if none
	autostartOff, matchy bool
}

func supervisorPrograms(lines []string, root string) []program {
	var out []program
	cur := -1
	for i, line := range lines {
		if sectionHeadRe.MatchString(line) {
			cur = -1
			if m := programHeadRe.FindStringSubmatch(line); m != nil {
				out = append(out, program{name: m[1], start: i, end: i, autostartLine: -1})
				cur = len(out) - 1
			}
			continue
		}
		if cur < 0 {
			continue
		}
		p := &out[cur]
		p.end = i
		if isComment(line) {
			continue
		}
		m := iniKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch strings.ToLower(m[1]) {
		case "command", "directory":
			p.matchy = p.matchy || MentionsRoot(m[2], root)
		case "autostart":
			p.autostartLine = i
			p.autostartOff = strings.EqualFold(m[2], "false")
		}
	}
	return out
}

func (e *Env) supervisorFiles() []cliFile {
	var out []cliFile
	for _, f := range e.cliFiles() {
		if f.kind == "supervisor" {
			out = append(out, f)
		}
	}
	return out
}

func (e *Env) programRunning(ctx context.Context, name string) bool {
	out, _, _, err := e.run(ctx, nil, "/usr/bin/supervisorctl", "status", name+":*")
	return err == nil && (strings.Contains(out, "RUNNING") || strings.Contains(out, "STARTING") || strings.Contains(out, "BACKOFF"))
}

func (e *Env) recordPath(root string) string {
	sum := sha256.Sum256([]byte(root))
	return e.path(filepath.Join(SiteRecordDir, hex.EncodeToString(sum[:8])+".json"))
}

func (e *Env) readRecord(root string) (*siteRecord, error) {
	b, err := os.ReadFile(e.recordPath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r siteRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("reading the restore record: %w", err)
	}
	if r.Root != root {
		return nil, fmt.Errorf("the restore record %s is for %s, not %s", e.recordPath(root), r.Root, root)
	}
	return &r, nil
}

func (e *Env) writeRecord(r *siteRecord) error {
	p := e.recordPath(r.Root)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// checkVhostHint validates the vhost Heimdall named: a file directly in
// sites-enabled, sites-available or conf.d.
func checkVhostHint(vhost string) error {
	if vhost == "" {
		return nil
	}
	dir := filepath.Dir(vhost)
	if len(vhost) > 255 || filepath.Clean(vhost) != vhost || strings.Contains(vhost, "..") ||
		(dir != "/etc/nginx/sites-enabled" && dir != "/etc/nginx/sites-available" && dir != "/etc/nginx/conf.d") {
		return fmt.Errorf("bad vhost %q: it must be a file in /etc/nginx/sites-enabled, sites-available or conf.d", vhost)
	}
	return nil
}

// disablePlan works out site.disable. The returned files are the vhosts
// to take out of nginx.
func (e *Env) disablePlan(ctx context.Context, root, vhost string) (*SitePlan, []vhostFile, *siteRecord, error) {
	p := &SitePlan{Action: "disable", Root: root, Vhosts: []PlanVhost{}, Supervisor: []PlanProgram{}, Cron: []PlanCron{}, Units: []PlanUnit{}, Pools: []PlanPool{}, Drift: []string{}, Notes: []string{}}
	record, err := e.readRecord(root)
	if err != nil {
		return nil, nil, nil, err
	}
	if record != nil {
		p.Disabled, p.DisabledAt = true, record.DisabledAt
	}
	files, err := e.enabledVhosts()
	if err != nil {
		return nil, nil, nil, err
	}
	var mine []vhostFile
	var myBlocks []serverBlock
	var otherSockets []string
	for _, v := range files {
		blocks, others := v.split(root)
		if len(blocks) == 0 {
			otherSockets = append(otherSockets, v.sockets(v.blocks)...)
			continue
		}
		if len(others) > 0 {
			p.Refusal = fmt.Sprintf("%s also serves %s; split it into its own file first", v.path, strings.Join(others, ", "))
		} else if v.defaultServer(blocks) {
			p.Refusal = fmt.Sprintf("%s is a default_server: requests for names no other site claims land on it, so disabling it changes what they get. Move default_server to another site first", v.path)
		}
		names := []string{}
		for _, b := range blocks {
			for _, n := range b.names {
				if !contains(names, n) {
					names = append(names, n)
				}
			}
		}
		pv := PlanVhost{Path: v.path, Kind: v.kind, Target: v.target, ServerNames: names}
		if v.kind == "file" {
			pv.HeldAt = filepath.Join(SiteHoldDir, filepath.Base(v.path))
		}
		p.Vhosts = append(p.Vhosts, pv)
		mine = append(mine, v)
		myBlocks = append(myBlocks, blocks...)
		if record != nil {
			p.Drift = append(p.Drift, fmt.Sprintf("%s serves %s again, though it was disabled at %s", v.path, root, record.DisabledAt))
		}
	}
	if vhost != "" {
		found := false
		for _, v := range mine {
			found = found || v.path == vhost || strings.TrimPrefix(v.real, e.Root) == vhost
		}
		if !found {
			p.Notes = append(p.Notes, fmt.Sprintf("%s, the vhost named in the request, isn't an enabled vhost serving %s; the files found are listed instead", vhost, root))
		}
	}

	for _, f := range e.supervisorFiles() {
		for _, pr := range supervisorPrograms(f.lines, root) {
			if !pr.matchy {
				continue
			}
			running := e.programRunning(ctx, pr.name)
			if pr.autostartOff && !running {
				continue // already off
			}
			if !programNameRe.MatchString(pr.name) {
				p.Refusal = fmt.Sprintf("supervisor program %q in %s has a name this can't pass to supervisorctl safely", pr.name, f.path)
			}
			p.Supervisor = append(p.Supervisor, PlanProgram{File: f.path, Program: pr.name, Running: running})
		}
	}
	for _, f := range e.cliFiles() {
		switch f.kind {
		case "cron":
			for _, line := range f.lines {
				if !isComment(line) && MentionsRoot(line, root) {
					p.Cron = append(p.Cron, PlanCron{File: f.path, Line: line})
				}
			}
		case "systemd":
			if !unitMentions(f.lines, root) {
				continue
			}
			unit := filepath.Base(f.path)
			if !unitNameRe.MatchString(unit) {
				p.Refusal = fmt.Sprintf("systemd unit %q has a name this can't pass to systemctl safely", unit)
				continue
			}
			u := PlanUnit{Unit: unit, Active: e.unitIs(ctx, "is-active", unit), Enabled: e.unitIs(ctx, "is-enabled", unit)}
			if u.Active || u.Enabled {
				p.Units = append(p.Units, u)
			}
		}
	}

	for _, v := range mine {
		blocks, _ := v.split(root)
		for _, sock := range v.sockets(blocks) {
			if contains(otherSockets, sock) {
				continue
			}
			if pool := e.poolFor(sock); pool != "" {
				p.Pools = append(p.Pools, PlanPool{File: pool, Socket: sock})
			}
		}
	}
	if len(p.Pools) > 0 {
		p.Notes = append(p.Notes, "PHP-FPM pools only this site uses are left running: an idle pool costs little, and stopping one can stop php-fpm when it's the last.")
	}
	if p.Refusal == "" && len(p.Vhosts) == 0 && len(p.Supervisor) == 0 && len(p.Cron) == 0 && len(p.Units) == 0 {
		if record != nil {
			p.Notes = append(p.Notes, "Already disabled: nothing serves or runs it.")
		} else if info, err := os.Stat(e.path(root)); err != nil || !info.IsDir() {
			p.Refusal = fmt.Sprintf("%s isn't a directory on this host, and nothing serves or runs it", root)
		} else {
			p.Refusal = fmt.Sprintf("no enabled nginx vhost, supervisor program, cron line or systemd unit serves or runs %s", root)
		}
	}
	if len(p.Vhosts) > 0 {
		p.Notes = append(p.Notes, "A hosting panel that manages this site may link its vhost again when it next rewrites the site's config. The plan for either action reports that as drift.")
	}
	return p, mine, record, nil
}

func unitMentions(lines []string, root string) bool {
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok && (strings.HasPrefix(k, "ExecStart") || k == "WorkingDirectory") && MentionsRoot(strings.TrimLeft(v, "-@!+:"), root) {
			return true
		}
	}
	return false
}

// poolFor finds the PHP-FPM pool file listening on socket.
func (e *Env) poolFor(socket string) string {
	paths, _ := filepath.Glob(e.path("/etc/php/*/fpm/pool.d/*.conf"))
	sort.Strings(paths)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if m := poolListenRe.FindStringSubmatch(line); m != nil && m[1] == socket {
				return strings.TrimPrefix(p, e.Root)
			}
		}
	}
	return ""
}

// PlanSite is the dry run for site.disable or site.enable.
func (e *Env) PlanSite(ctx context.Context, action, root, vhost string) (*SitePlan, error) {
	if err := CheckRoot(root); err != nil {
		return nil, err
	}
	if err := checkVhostHint(vhost); err != nil {
		return nil, err
	}
	switch action {
	case "disable":
		p, _, _, err := e.disablePlan(ctx, root, vhost)
		return p, err
	case "enable":
		p, _, err := e.enablePlan(ctx, root, vhost)
		return p, err
	}
	return nil, fmt.Errorf("unknown action %q", action)
}

// undo is one step's way back, run in reverse order when a later step fails.
type undo struct {
	what string
	fn   func() error
}

func (e *Env) unwind(steps []undo) error {
	var errs []error
	for i := len(steps) - 1; i >= 0; i-- {
		if err := steps[i].fn(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", steps[i].what, err))
		}
	}
	return errors.Join(errs...)
}

func (e *Env) failWith(cause error, steps []undo) error {
	if err := e.unwind(steps); err != nil {
		return fmt.Errorf("%w; putting things back failed too: %v", cause, err)
	}
	return fmt.Errorf("%w; everything this run changed was put back", cause)
}

func (e *Env) reloadNginx(ctx context.Context) error {
	if err := e.check(ctx, "nginx -t", "/usr/sbin/nginx", "-t"); err != nil {
		return err
	}
	return e.check(ctx, "reloading nginx", "/usr/bin/systemctl", "reload", "nginx")
}

func (e *Env) stamp() string { return e.Now().UTC().Format("2006-01-02T15:04:05Z") }

// DisableSite runs site.disable.
func (e *Env) DisableSite(ctx context.Context, root, vhost string) error {
	if err := CheckRoot(root); err != nil {
		return err
	}
	if err := checkVhostHint(vhost); err != nil {
		return err
	}
	plan, vhosts, record, err := e.disablePlan(ctx, root, vhost)
	if err != nil {
		return err
	}
	if plan.Refusal != "" {
		return errors.New("refused: " + plan.Refusal)
	}
	for _, n := range plan.Notes {
		e.say("%s", n)
	}
	if len(plan.Vhosts)+len(plan.Supervisor)+len(plan.Cron)+len(plan.Units) == 0 {
		return nil
	}
	if record == nil {
		record = &siteRecord{Root: root}
	}
	record.DisabledAt = e.stamp()
	var steps []undo

	if len(vhosts) > 0 {
		// Registered first, so it runs last on the way back: after every
		// vhost is back in place.
		steps = append(steps, undo{"reloading nginx", func() error { return e.reloadNginx(ctx) }})
	}
	for _, v := range vhosts {
		rv := recVhost{Path: v.path, Kind: v.kind, Target: v.target}
		if v.kind == "symlink" {
			if err := os.Remove(v.real0(e.Root)); err != nil {
				return e.failWith(err, steps)
			}
			path, target := e.path(v.path), v.target
			steps = append(steps, undo{"linking " + v.path, func() error { return os.Symlink(target, path) }})
			e.say("Unlinked %s (-> %s)", v.path, v.target)
		} else {
			held, err := e.holdPath(filepath.Base(v.path))
			if err != nil {
				return e.failWith(err, steps)
			}
			from := e.path(v.path)
			info, err := os.Stat(from)
			if err != nil {
				return e.failWith(err, steps)
			}
			mode := info.Mode().Perm()
			if err := os.Rename(from, e.path(held)); err != nil {
				return e.failWith(err, steps)
			}
			to := e.path(held)
			steps = append(steps, undo{"moving back " + v.path, func() error {
				if err := os.Rename(to, from); err != nil {
					return err
				}
				return os.Chmod(from, mode)
			}})
			if err := os.Chmod(to, 0o644); err != nil {
				return e.failWith(err, steps)
			}
			rv.HeldAt, rv.Mode = held, uint32(mode)
			e.say("Moved %s to %s", v.path, held)
		}
		record.addVhost(rv)
	}
	if len(vhosts) > 0 {
		if err := e.reloadNginx(ctx); err != nil {
			return e.failWith(err, steps)
		}
	}

	// Cron: comment the lines out with a marker.
	cronEdits := map[string]*edit{}
	var cronOrder []string
	for _, c := range plan.Cron {
		if cronEdits[c.File] == nil {
			ed, err := readEdit(e.path(c.File), c.File, "cron")
			if err != nil {
				return e.failWith(err, steps)
			}
			ed.new = ed.old
			cronEdits[c.File] = &ed
			cronOrder = append(cronOrder, c.File)
		}
	}
	for _, file := range cronOrder {
		ed := cronEdits[file]
		lines := strings.Split(string(ed.old), "\n")
		for i, line := range lines {
			if !isComment(line) && MentionsRoot(line, root) {
				lines[i] = CronMarker + line
				ed.changes++
			}
		}
		ed.new = []byte(strings.Join(lines, "\n"))
		if err := writeLike(*ed, ed.new); err != nil {
			return e.failWith(err, steps)
		}
		saved := *ed
		steps = append(steps, undo{"putting back " + file, func() error { return writeLike(saved, saved.old) }})
		e.say("%s: commented out %d line(s)", file, ed.changes)
	}
	for _, c := range plan.Cron {
		record.addCron(c)
	}

	// Supervisor: autostart=false, then stop.
	if len(plan.Supervisor) > 0 {
		byFile := map[string][]PlanProgram{}
		var order []string
		for _, pr := range plan.Supervisor {
			if byFile[pr.File] == nil {
				order = append(order, pr.File)
			}
			byFile[pr.File] = append(byFile[pr.File], pr)
		}
		var running []string
		steps = append(steps, undo{"restarting supervisor programs", func() error {
			if err := e.supervisorUpdate(ctx); err != nil {
				return err
			}
			for _, name := range running {
				if err := e.check(ctx, "starting "+name, "/usr/bin/supervisorctl", "start", name+":*"); err != nil {
					return err
				}
			}
			return nil
		}})
		for _, file := range order {
			ed, err := readEdit(e.path(file), file, "supervisor")
			if err != nil {
				return e.failWith(err, steps)
			}
			lines := strings.Split(string(ed.old), "\n")
			programs := supervisorPrograms(lines, root)
			// Edit from the bottom up, so inserted lines don't shift the rest.
			for i := len(programs) - 1; i >= 0; i-- {
				pr := programs[i]
				var mine *PlanProgram
				for j := range byFile[file] {
					if byFile[file][j].Program == pr.name {
						mine = &byFile[file][j]
					}
				}
				if mine == nil {
					continue
				}
				rp := recProgram{File: file, Program: pr.name, Running: mine.Running}
				if pr.autostartLine >= 0 {
					rp.Autostart = lines[pr.autostartLine]
					lines[pr.autostartLine] = "autostart=false"
				} else {
					lines = append(lines[:pr.start+1], append([]string{"autostart=false"}, lines[pr.start+1:]...)...)
				}
				record.addProgram(rp)
				if mine.Running {
					running = append(running, pr.name)
				}
			}
			ed.new = []byte(strings.Join(lines, "\n"))
			if err := writeLike(ed, ed.new); err != nil {
				return e.failWith(err, steps)
			}
			saved := ed
			steps = append(steps, undo{"putting back " + file, func() error { return writeLike(saved, saved.old) }})
			e.say("%s: autostart is off", file)
		}
		if err := e.supervisorUpdate(ctx); err != nil {
			return e.failWith(err, steps)
		}
		for _, pr := range plan.Supervisor {
			if err := e.check(ctx, "stopping "+pr.Program, "/usr/bin/supervisorctl", "stop", pr.Program+":*"); err != nil {
				return e.failWith(err, steps)
			}
			e.say("Stopped supervisor program %s", pr.Program)
		}
	}

	// systemd: disable and stop.
	for _, u := range plan.Units {
		if err := e.check(ctx, "disabling "+u.Unit, "/usr/bin/systemctl", "disable", "--now", u.Unit); err != nil {
			return e.failWith(err, steps)
		}
		u := u
		steps = append(steps, undo{"starting " + u.Unit, func() error { return e.restoreUnit(ctx, u) }})
		record.addUnit(u)
		e.say("Disabled and stopped %s", u.Unit)
	}

	// Verify.
	after, err := e.enabledVhosts()
	if err != nil {
		return e.failWith(err, steps)
	}
	for _, v := range after {
		if mine, _ := v.split(root); len(mine) > 0 {
			return e.failWith(fmt.Errorf("%s still serves %s", v.path, root), steps)
		}
	}
	for _, pr := range plan.Supervisor {
		if e.programRunning(ctx, pr.Program) {
			return e.failWith(fmt.Errorf("supervisor program %s is still running", pr.Program), steps)
		}
	}
	for _, u := range plan.Units {
		if e.unitIs(ctx, "is-active", u.Unit) {
			return e.failWith(fmt.Errorf("%s is still active", u.Unit), steps)
		}
	}
	if err := e.writeRecord(record); err != nil {
		return e.failWith(fmt.Errorf("writing the restore record: %w", err), steps)
	}
	e.say("%s is disabled. Nothing was deleted; site.enable puts it back (restore record %s).", root, strings.TrimPrefix(e.recordPath(root), e.Root))
	return nil
}

// The add methods keep the first entry for each thing: a second disable
// (after drift) must not record the state the first one left as "before".

func (r *siteRecord) addVhost(v recVhost) {
	for i, x := range r.Vhosts {
		if x.Path == v.Path {
			r.Vhosts[i] = v // the newest way it was taken out is how it comes back
			return
		}
	}
	r.Vhosts = append(r.Vhosts, v)
}

func (r *siteRecord) addCron(c PlanCron) {
	for _, x := range r.Cron {
		if x == c {
			return
		}
	}
	r.Cron = append(r.Cron, c)
}

func (r *siteRecord) addProgram(p recProgram) {
	for _, x := range r.Supervisor {
		if x.File == p.File && x.Program == p.Program {
			return
		}
	}
	r.Supervisor = append(r.Supervisor, p)
}

func (r *siteRecord) addUnit(u PlanUnit) {
	for _, x := range r.Units {
		if x.Unit == u.Unit {
			return
		}
	}
	r.Units = append(r.Units, u)
}

// real0 is the vhost's path as listed (the link itself, not its target).
func (v vhostFile) real0(root string) string { return filepath.Join(root, v.path) }

// heldMode is the permissions a held file had before it was disabled,
// or 0 when the record doesn't say (records from v0.19.0).
func (r *siteRecord) heldMode(path string) os.FileMode {
	if r == nil {
		return 0
	}
	for _, v := range r.Vhosts {
		if v.Path == path {
			return os.FileMode(v.Mode).Perm()
		}
	}
	return 0
}

func (e *Env) holdPath(name string) (string, error) {
	dir := e.path(SiteHoldDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// MkdirAll is subject to the umask, and the folder may predate this.
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	held := filepath.Join(SiteHoldDir, name)
	for i := 2; ; i++ {
		if _, err := os.Lstat(e.path(held)); errors.Is(err, fs.ErrNotExist) {
			return held, nil
		}
		if i > 100 {
			return "", fmt.Errorf("no free name for %s in %s", name, SiteHoldDir)
		}
		held = filepath.Join(SiteHoldDir, fmt.Sprintf("%s.%d", name, i))
	}
}

func (e *Env) supervisorUpdate(ctx context.Context) error {
	if err := e.check(ctx, "supervisorctl reread", "/usr/bin/supervisorctl", "reread"); err != nil {
		return err
	}
	return e.check(ctx, "supervisorctl update", "/usr/bin/supervisorctl", "update")
}

func (e *Env) restoreUnit(ctx context.Context, u PlanUnit) error {
	if u.Enabled {
		if err := e.check(ctx, "enabling "+u.Unit, "/usr/bin/systemctl", "enable", u.Unit); err != nil {
			return err
		}
	}
	if u.Active {
		return e.check(ctx, "starting "+u.Unit, "/usr/bin/systemctl", "start", u.Unit)
	}
	return nil
}

// availableFor finds the sites-available files serving root, and only
// root, for an enable without a restore record.
func (e *Env) availableFor(root, vhost string) ([]vhostFile, []string, error) {
	var notes []string
	paths, err := filepath.Glob(e.path("/etc/nginx/sites-available/*"))
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	if vhost != "" && filepath.Dir(vhost) == "/etc/nginx/sites-available" {
		paths = []string{e.path(vhost)}
	}
	var out []vhostFile
	for _, p := range paths {
		v, ok, err := e.readVhost(p)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		mine, others := v.split(root)
		if len(mine) == 0 {
			if vhost != "" && v.path == vhost {
				notes = append(notes, fmt.Sprintf("%s doesn't serve %s", vhost, root))
			}
			continue
		}
		if len(others) > 0 {
			notes = append(notes, fmt.Sprintf("%s also serves %s, so it isn't linked", v.path, strings.Join(others, ", ")))
			continue
		}
		out = append(out, v)
	}
	return out, notes, nil
}

// enablePlan works out site.enable from the restore record, or, without
// one, from sites-available.
func (e *Env) enablePlan(ctx context.Context, root, vhost string) (*SitePlan, *siteRecord, error) {
	p := &SitePlan{Action: "enable", Root: root, Vhosts: []PlanVhost{}, Supervisor: []PlanProgram{}, Cron: []PlanCron{}, Units: []PlanUnit{}, Pools: []PlanPool{}, Drift: []string{}, Notes: []string{}}
	record, err := e.readRecord(root)
	if err != nil {
		return nil, nil, err
	}
	enabled, err := e.enabledVhosts()
	if err != nil {
		return nil, nil, err
	}
	served := []string{}
	for _, v := range enabled {
		if mine, _ := v.split(root); len(mine) > 0 {
			served = append(served, v.path)
		}
	}
	for _, f := range e.cliFiles() {
		if f.kind != "cron" {
			continue
		}
		for _, line := range f.lines {
			if rest, ok := strings.CutPrefix(line, CronMarker); ok && MentionsRoot(rest, root) {
				p.Cron = append(p.Cron, PlanCron{File: f.path, Line: rest})
			}
		}
	}
	if record == nil {
		if len(served) > 0 {
			p.Notes = append(p.Notes, fmt.Sprintf("Already served by %s; there's no restore record.", strings.Join(served, ", ")))
			return p, nil, nil
		}
		avail, notes, err := e.availableFor(root, vhost)
		if err != nil {
			return nil, nil, err
		}
		p.Notes = append(p.Notes, notes...)
		for _, v := range avail {
			link := filepath.Join("/etc/nginx/sites-enabled", filepath.Base(v.path))
			if _, err := os.Lstat(e.path(link)); err == nil {
				p.Notes = append(p.Notes, fmt.Sprintf("%s already exists, so %s isn't linked", link, v.path))
				continue
			}
			mine, _ := v.split(root)
			names := []string{}
			for _, b := range mine {
				names = append(names, b.names...)
			}
			p.Vhosts = append(p.Vhosts, PlanVhost{Path: link, Kind: "symlink", Target: v.path, ServerNames: names})
		}
		p.Notes = append(p.Notes, "There's no restore record, so this links the vhost back and uncomments cron lines site.disable marked, but can't restore supervisor programs or systemd units.")
		if len(p.Vhosts) == 0 && len(p.Cron) == 0 {
			p.Refusal = fmt.Sprintf("there's no restore record for %s and no file in /etc/nginx/sites-available serves it alone", root)
		}
		return p, nil, nil
	}
	p.Disabled, p.DisabledAt = true, record.DisabledAt
	for _, s := range served {
		p.Drift = append(p.Drift, fmt.Sprintf("%s already serves %s again", s, root))
	}
	for _, v := range record.Vhosts {
		if _, err := os.Lstat(e.path(v.Path)); err == nil {
			p.Notes = append(p.Notes, fmt.Sprintf("%s exists again, so it's left as it is", v.Path))
			continue
		}
		if v.Kind == "file" {
			if _, err := os.Stat(e.path(v.HeldAt)); err != nil {
				p.Refusal = fmt.Sprintf("%s, where %s was held, is gone", v.HeldAt, v.Path)
			}
		}
		p.Vhosts = append(p.Vhosts, PlanVhost{Path: v.Path, Kind: v.Kind, Target: v.Target, HeldAt: v.HeldAt, ServerNames: []string{}})
	}
	for _, pr := range record.Supervisor {
		p.Supervisor = append(p.Supervisor, PlanProgram{File: pr.File, Program: pr.Program, Running: pr.Running})
	}
	p.Units = append(p.Units, record.Units...)
	return p, record, nil
}

// EnableSite runs site.enable.
func (e *Env) EnableSite(ctx context.Context, root, vhost string) error {
	if err := CheckRoot(root); err != nil {
		return err
	}
	if err := checkVhostHint(vhost); err != nil {
		return err
	}
	plan, record, err := e.enablePlan(ctx, root, vhost)
	if err != nil {
		return err
	}
	if plan.Refusal != "" {
		return errors.New("refused: " + plan.Refusal)
	}
	for _, n := range append(plan.Drift, plan.Notes...) {
		e.say("%s", n)
	}
	var steps []undo
	if len(plan.Vhosts) > 0 {
		steps = append(steps, undo{"reloading nginx", func() error { return e.reloadNginx(ctx) }})
	}
	for _, v := range plan.Vhosts {
		path := e.path(v.Path)
		if v.Kind == "symlink" {
			if err := os.Symlink(v.Target, path); err != nil {
				return e.failWith(err, steps)
			}
			steps = append(steps, undo{"unlinking " + v.Path, func() error { return os.Remove(path) }})
			e.say("Linked %s -> %s", v.Path, v.Target)
		} else {
			held := e.path(v.HeldAt)
			if err := os.Rename(held, path); err != nil {
				return e.failWith(err, steps)
			}
			steps = append(steps, undo{"moving away " + v.Path, func() error {
				if err := os.Rename(path, held); err != nil {
					return err
				}
				return os.Chmod(held, 0o644)
			}})
			if mode := record.heldMode(v.Path); mode != 0 {
				if err := os.Chmod(path, mode); err != nil {
					return e.failWith(err, steps)
				}
			}
			e.say("Moved %s back to %s", v.HeldAt, v.Path)
		}
	}
	if len(plan.Vhosts) > 0 {
		if err := e.reloadNginx(ctx); err != nil {
			return e.failWith(err, steps)
		}
	}

	files := map[string]bool{}
	for _, c := range plan.Cron {
		files[c.File] = true
	}
	for _, file := range sortedKeys(files) {
		ed, err := readEdit(e.path(file), file, "cron")
		if err != nil {
			return e.failWith(err, steps)
		}
		lines := strings.Split(string(ed.old), "\n")
		for i, line := range lines {
			if rest, ok := strings.CutPrefix(line, CronMarker); ok && MentionsRoot(rest, root) {
				lines[i] = rest
				ed.changes++
			}
		}
		ed.new = []byte(strings.Join(lines, "\n"))
		if err := writeLike(ed, ed.new); err != nil {
			return e.failWith(err, steps)
		}
		saved := ed
		steps = append(steps, undo{"putting back " + file, func() error { return writeLike(saved, saved.old) }})
		e.say("%s: uncommented %d line(s)", file, ed.changes)
	}

	if record != nil && len(record.Supervisor) > 0 {
		byFile := map[string][]recProgram{}
		for _, pr := range record.Supervisor {
			byFile[pr.File] = append(byFile[pr.File], pr)
		}
		steps = append(steps, undo{"supervisorctl update", func() error { return e.supervisorUpdate(ctx) }})
		for _, file := range sortedKeys(toSet(byFile)) {
			ed, err := readEdit(e.path(file), file, "supervisor")
			if err != nil {
				e.say("%s: %v; its programs weren't restored", file, err)
				continue
			}
			lines := strings.Split(string(ed.old), "\n")
			programs := supervisorPrograms(lines, root)
			for i := len(programs) - 1; i >= 0; i-- {
				pr := programs[i]
				for _, rp := range byFile[file] {
					if rp.Program != pr.name || pr.autostartLine < 0 {
						continue
					}
					if rp.Autostart == "" {
						lines = append(lines[:pr.autostartLine], lines[pr.autostartLine+1:]...)
					} else {
						lines[pr.autostartLine] = rp.Autostart
					}
				}
			}
			ed.new = []byte(strings.Join(lines, "\n"))
			if err := writeLike(ed, ed.new); err != nil {
				return e.failWith(err, steps)
			}
			saved := ed
			steps = append(steps, undo{"putting back " + file, func() error { return writeLike(saved, saved.old) }})
			e.say("%s: autostart restored", file)
		}
		if err := e.supervisorUpdate(ctx); err != nil {
			return e.failWith(err, steps)
		}
		for _, pr := range record.Supervisor {
			if !pr.Running {
				continue
			}
			if err := e.check(ctx, "starting "+pr.Program, "/usr/bin/supervisorctl", "start", pr.Program+":*"); err != nil {
				return e.failWith(err, steps)
			}
			e.say("Started supervisor program %s", pr.Program)
		}
	}
	if record != nil {
		for _, u := range record.Units {
			if err := e.restoreUnit(ctx, u); err != nil {
				return e.failWith(err, steps)
			}
			e.say("Restored %s (enabled %t, active %t)", u.Unit, u.Enabled, u.Active)
		}
		if err := os.Remove(e.recordPath(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			e.say("Couldn't remove the restore record: %v", err)
		}
	}
	e.say("%s is enabled again.", root)
	return nil
}

func toSet[V any](m map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
