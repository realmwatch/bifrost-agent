package state

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/redact"
)

// Package is one installed package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// Update is one pending update.
type Update struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Candidate string `json:"candidate"`
	Security  bool   `json:"security"`
	// Held is true for a package held at its version (apt-mark hold, dnf
	// versionlock): upgrading it fails until it is unheld.
	Held bool `json:"held"`
}

// ServiceStatus is a systemd unit's state.
type ServiceStatus struct {
	Unit          string `json:"unit"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	LoadState     string `json:"load_state"`
	UnitFileState string `json:"unit_file_state"`
	Since         string `json:"since"`
}

// Mount is one mounted filesystem.
type Mount struct {
	Mount      string `json:"mount"`
	FS         string `json:"fs"`
	SizeBytes  uint64 `json:"size_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
	AvailBytes uint64 `json:"avail_bytes"`
}

// Memory is the memory summary.
type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapFreeBytes  uint64 `json:"swap_free_bytes"`
}

// Port is one listening socket.
type Port struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// Session is one logged-in user.
type Session struct {
	User  string `json:"user"`
	TTY   string `json:"tty"`
	From  string `json:"from"`
	Since string `json:"since"`
}

func toolOS(_ context.Context, e *Env, _ map[string]any) (any, error) {
	osr, err := e.OSRelease()
	if err != nil {
		return nil, err
	}
	res := map[string]any{
		"id": osr["ID"], "version_id": osr["VERSION_ID"], "pretty_name": osr["PRETTY_NAME"],
		"os_release": osr,
	}
	res["kernel"], _ = e.Kernel()
	res["uptime_seconds"], _ = e.Uptime()
	res["machine_id"], _ = e.MachineID()
	if e.Hostname != nil {
		res["hostname"], _ = e.Hostname()
	}
	return res, nil
}

// Packages lists installed packages.
func (e *Env) Packages(ctx context.Context) ([]Package, error) {
	if err := e.requirePM(); err != nil {
		return nil, err
	}
	if e.PackageManager == catalog.PackageManagerApt {
		out, err := e.runOK(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n")
		if err != nil {
			return nil, err
		}
		return ParseDpkgQuery(out), nil
	}
	out, err := e.runOK(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	if err != nil {
		return nil, err
	}
	return ParseRpmQuery(out), nil
}

func toolPackages(ctx context.Context, e *Env, args map[string]any) (any, error) {
	pkgs, err := e.Packages(ctx)
	if err != nil {
		return nil, err
	}
	names, _ := args["names"].([]any)
	if len(names) == 0 {
		return pkgs, nil
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n.(string)] = true
	}
	out := []Package{}
	for _, p := range pkgs {
		if want[p.Name] {
			out = append(out, p)
		}
	}
	return out, nil
}

// ParseDpkgQuery parses dpkg-query output in the agent's format, keeping
// installed packages only.
func ParseDpkgQuery(out string) []Package {
	pkgs := []Package{}
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 4 || len(f[3]) < 2 || f[3][1] != 'i' {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[0], Version: f[1], Arch: f[2]})
	}
	return pkgs
}

// ParseRpmQuery parses rpm -qa output in the agent's format.
func ParseRpmQuery(out string) []Package {
	pkgs := []Package{}
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "gpg-pubkey" {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[0], Version: f[1], Arch: f[2]})
	}
	return pkgs
}

func toolPendingUpdates(ctx context.Context, e *Env, args map[string]any) (any, error) {
	if err := e.requirePM(); err != nil {
		return nil, err
	}
	refresh, _ := args["refresh"].(bool)
	fallback, _ := args["fallback"].(bool)
	var refreshErr error
	if refresh {
		// Refresh the package lists first, so candidates are current.
		refreshErr = e.refreshLists(ctx)
		if refreshErr != nil && !fallback {
			return nil, refreshErr
		}
	}
	updates, err := e.pendingUpdates(ctx)
	if err != nil || !fallback {
		return updates, err
	}
	// With fallback, a failed refresh doesn't fail the query: the updates
	// come from the lists the server already has, and the answer says so.
	report := RefreshReport{Requested: refresh, OK: refresh && refreshErr == nil, ListsUpdatedAt: e.listsUpdatedAt()}
	if refreshErr != nil {
		report.Error = refreshErr.Error()
	}
	return PendingUpdatesReport{Updates: updates, Refresh: report}, nil
}

// PendingUpdatesReport is pending_updates' answer when the hub asks for a
// fallback: the updates, and whether the package lists were refreshed.
type PendingUpdatesReport struct {
	Updates []Update      `json:"updates"`
	Refresh RefreshReport `json:"refresh"`
}

// RefreshReport says whether the package lists were refreshed first.
type RefreshReport struct {
	Requested bool   `json:"requested"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	// ListsUpdatedAt is when the lists the updates came from were last
	// refreshed, RFC 3339 in UTC; empty if unknown.
	ListsUpdatedAt string `json:"lists_updated_at"`
}

// listReserve is the part of the query's time a refresh leaves for listing
// the updates afterwards.
const listReserve = 15 * time.Second

// aptLockRe matches apt's message when another process holds its lock.
var aptLockRe = regexp.MustCompile(`Could not get lock (\S+?)\.? It is held by process ([0-9]+) \(([^)]*)\)`)

// refreshLists refreshes the package lists through sudo, and says plainly
// when another process holds apt's lock or the time limit runs out.
func (e *Env) refreshLists(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > 2*listReserve {
		// Stop early enough to still list the updates from the lists the
		// server has.
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-listReserve))
		defer cancel()
	}
	_, errOut, code, err := e.runCapture(ctx, e.privileged(catalog.PrivilegedReads["pending_updates"][e.PackageManager])...)
	if err != nil {
		return fmt.Errorf("refreshing the package lists: %w", err)
	}
	if code == 0 {
		return nil
	}
	if m := aptLockRe.FindStringSubmatch(errOut); m != nil {
		holder := m[3] + ", PID " + m[2]
		if unit := e.unitOf(m[2]); unit != "" {
			holder += ", from " + unit
		}
		return fmt.Errorf("refreshing the package lists: apt is busy: another process (%s) holds %s", holder, m[1])
	}
	if tail := stderrTail(errOut); tail != "" {
		return fmt.Errorf("refreshing the package lists: %s exited with status %d: %s", commandName(e.privileged(catalog.PrivilegedReads["pending_updates"][e.PackageManager])), code, tail)
	}
	return fmt.Errorf("refreshing the package lists: %s exited with status %d", commandName(e.privileged(catalog.PrivilegedReads["pending_updates"][e.PackageManager])), code)
}

// unitOf is the systemd unit a process runs in, from /proc/<pid>/cgroup,
// or "" when it isn't in one.
func (e *Env) unitOf(pid string) string {
	cg, err := e.readFile("/proc/" + pid + "/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range lines(cg) {
		unit := filepath.Base(strings.TrimSpace(line))
		if strings.HasSuffix(unit, ".service") || strings.HasSuffix(unit, ".scope") {
			return unit
		}
	}
	return ""
}

// listsUpdatedAt is when apt's lists were last refreshed: the newest
// Release file under /var/lib/apt/lists. dnf reports "".
func (e *Env) listsUpdatedAt() string {
	if e.PackageManager != catalog.PackageManagerApt {
		return ""
	}
	entries, err := os.ReadDir(e.Path("/var/lib/apt/lists"))
	if err != nil {
		return ""
	}
	var newest time.Time
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "Release") {
			continue
		}
		if info, err := entry.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if newest.IsZero() {
		return ""
	}
	return utcRFC3339(newest)
}

// pendingUpdates lists the upgrades the package lists offer now.
func (e *Env) pendingUpdates(ctx context.Context) ([]Update, error) {
	held, err := e.HeldPackages(ctx)
	if err != nil {
		return nil, err
	}
	if e.PackageManager == catalog.PackageManagerApt {
		out, err := e.runOK(ctx, "apt", "list", "--upgradable")
		if err != nil {
			return nil, err
		}
		return markHeld(ParseAptUpgradable(out), held), nil
	}
	out, code, err := e.run(ctx, "dnf", "-q", "check-update")
	if err != nil {
		return nil, err
	}
	if code != 0 && code != 100 {
		return nil, fmt.Errorf("dnf check-update exited with status %d", code)
	}
	pkgs, err := e.Packages(ctx)
	if err != nil {
		return nil, err
	}
	current := map[string]string{}
	for _, p := range pkgs {
		current[p.Name] = p.Version
	}
	security := map[string]bool{}
	if sec, code, err := e.run(ctx, "dnf", "-q", "updateinfo", "list", "--security"); err == nil && code == 0 {
		security = ParseDnfSecurity(sec)
	}
	return markHeld(ParseDnfCheckUpdate(out, current, security), held), nil
}

func markHeld(ups []Update, held map[string]bool) []Update {
	for i := range ups {
		ups[i].Held = held[ups[i].Name]
	}
	return ups
}

// ParseAptUpgradable parses `apt list --upgradable`.
func ParseAptUpgradable(out string) []Update {
	ups := []Update{}
	for _, line := range lines(out) {
		// openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
		f := strings.Fields(line)
		if len(f) < 6 || !strings.Contains(f[0], "/") || f[3] != "[upgradable" {
			continue
		}
		name, suites, _ := strings.Cut(f[0], "/")
		ups = append(ups, Update{
			Name: name, Candidate: f[1], Current: strings.TrimSuffix(f[5], "]"),
			Security: strings.Contains(suites, "-security"),
		})
	}
	return ups
}

// ParseDnfCheckUpdate parses `dnf -q check-update`.
func ParseDnfCheckUpdate(out string, current map[string]string, security map[string]bool) []Update {
	ups := []Update{}
	seen := map[string]bool{}
	for _, line := range lines(out) {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(line, " ") {
			continue
		}
		dot := strings.LastIndex(f[0], ".")
		if dot <= 0 {
			continue
		}
		name := f[0][:dot]
		if seen[name] {
			continue
		}
		seen[name] = true
		ups = append(ups, Update{Name: name, Current: current[name], Candidate: f[1], Security: security[name]})
	}
	return ups
}

// ParseDnfSecurity parses `dnf -q updateinfo list --security` into the set
// of package names with a security advisory.
func ParseDnfSecurity(out string) map[string]bool {
	names := map[string]bool{}
	for _, line := range lines(out) {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		if name := nevraName(f[2]); name != "" {
			names[name] = true
		}
	}
	return names
}

// nevraName extracts the name from name-[epoch:]version-release.arch.
func nevraName(nevra string) string {
	if dot := strings.LastIndex(nevra, "."); dot > 0 {
		nevra = nevra[:dot]
	}
	for range 2 {
		dash := strings.LastIndex(nevra, "-")
		if dash <= 0 {
			return ""
		}
		nevra = nevra[:dash]
	}
	return nevra
}

// ServiceStatus reads a unit's state from systemctl show.
func (e *Env) ServiceStatus(ctx context.Context, unit string) (ServiceStatus, error) {
	out, err := e.runOK(ctx, "systemctl", "show", unit, "--no-pager",
		"-p", "Id", "-p", "ActiveState", "-p", "SubState", "-p", "LoadState",
		"-p", "UnitFileState", "-p", "ActiveEnterTimestamp")
	if err != nil {
		return ServiceStatus{}, err
	}
	return ParseSystemctlShow(unit, out), nil
}

func toolServiceStatus(ctx context.Context, e *Env, args map[string]any) (any, error) {
	return e.ServiceStatus(ctx, args["unit"].(string))
}

// ParseSystemctlShow parses key=value output from systemctl show, run with
// TZ=UTC.
func ParseSystemctlShow(unit, out string) ServiceStatus {
	kv := map[string]string{}
	for _, line := range lines(out) {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
		}
	}
	s := ServiceStatus{
		Unit: unit, ActiveState: kv["ActiveState"], SubState: kv["SubState"],
		LoadState: kv["LoadState"], UnitFileState: kv["UnitFileState"],
	}
	if ts := kv["ActiveEnterTimestamp"]; ts != "" {
		if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", ts); err == nil {
			s.Since = utcRFC3339(t)
		} else {
			s.Since = ts
		}
	}
	return s
}

func toolJournal(ctx context.Context, e *Env, args map[string]any) (any, error) {
	n := intArg(args, "lines", 100)
	out, err := e.runOK(ctx, "journalctl", "-u", args["unit"].(string), "-n", strconv.Itoa(n), "-o", "short-iso", "--no-pager", "-q")
	if err != nil {
		return nil, err
	}
	return map[string]any{"lines": ParseJournal(out)}, nil
}

// ParseJournal splits journalctl output into redacted lines.
func ParseJournal(out string) []string {
	res := []string{}
	for _, line := range lines(out) {
		if strings.HasPrefix(line, "-- ") && strings.HasSuffix(line, " --") {
			continue
		}
		res = append(res, redact.String(line))
	}
	return res
}

var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true,
	"cgroup2": true, "securityfs": true, "pstore": true, "bpf": true, "tracefs": true, "debugfs": true,
	"configfs": true, "fusectl": true, "mqueue": true, "hugetlbfs": true, "autofs": true,
	"binfmt_misc": true, "rpc_pipefs": true, "nsfs": true, "overlay": true, "squashfs": true,
	"efivarfs": true, "ramfs": true, "selinuxfs": true, "fuse.lxcfs": true, "fuse.portal": true,
	"fuse.gvfsd-fuse": true,
}

// ParseMounts parses /proc/mounts, keeping real filesystems, one per mount
// point.
func ParseMounts(out string) []Mount {
	res := []Mount{}
	seen := map[string]bool{}
	for _, line := range lines(out) {
		f := strings.Fields(line)
		if len(f) < 3 || pseudoFS[f[2]] {
			continue
		}
		mp := unescapeMount(f[1])
		if seen[mp] {
			continue
		}
		seen[mp] = true
		res = append(res, Mount{Mount: mp, FS: f[2]})
	}
	return res
}

func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func toolDisk(_ context.Context, e *Env, _ map[string]any) (any, error) {
	data, err := e.readFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	mounts := ParseMounts(data)
	out := []Mount{}
	for _, m := range mounts {
		st, err := e.Statfs(m.Mount)
		if err != nil {
			continue
		}
		m.SizeBytes = st.Blocks * st.BlockSize
		m.UsedBytes = (st.Blocks - st.BlocksFree) * st.BlockSize
		m.AvailBytes = st.BlocksAvail * st.BlockSize
		out = append(out, m)
	}
	return out, nil
}

// ParseMeminfo parses /proc/meminfo.
func ParseMeminfo(out string) (Memory, error) {
	kb := map[string]uint64{}
	for _, line := range lines(out) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		kb[k] = n
	}
	if _, ok := kb["MemTotal"]; !ok {
		return Memory{}, fmt.Errorf("meminfo: no MemTotal")
	}
	return Memory{
		TotalBytes: kb["MemTotal"] * 1024, AvailableBytes: kb["MemAvailable"] * 1024,
		SwapTotalBytes: kb["SwapTotal"] * 1024, SwapFreeBytes: kb["SwapFree"] * 1024,
	}, nil
}

func toolMemory(_ context.Context, e *Env, _ map[string]any) (any, error) {
	data, err := e.readFile("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	return ParseMeminfo(data)
}

func toolPorts(ctx context.Context, e *Env, _ map[string]any) (any, error) {
	out, err := e.runOK(ctx, "ss", "-tulnpH")
	if err != nil {
		return nil, err
	}
	return ParseSS(out), nil
}

// ParseSS parses `ss -tulnpH`.
func ParseSS(out string) []Port {
	res := []Port{}
	for _, line := range lines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		colon := strings.LastIndex(local, ":")
		if colon < 0 {
			continue
		}
		port, err := strconv.Atoi(local[colon+1:])
		if err != nil {
			continue
		}
		addr := strings.TrimSuffix(strings.TrimPrefix(local[:colon], "["), "]")
		p := Port{Proto: f[0], Address: addr, Port: port}
		if len(f) >= 7 {
			p.Process = ssProcess(strings.Join(f[6:], " "))
		}
		res = append(res, p)
	}
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].Proto != res[j].Proto {
			return res[i].Proto < res[j].Proto
		}
		return res[i].Port < res[j].Port
	})
	return res
}

func ssProcess(s string) string {
	start := strings.Index(s, `(("`)
	if start < 0 {
		return ""
	}
	rest := s[start+3:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func toolSessions(ctx context.Context, e *Env, _ map[string]any) (any, error) {
	out, err := e.runOK(ctx, "who")
	if err != nil {
		return nil, err
	}
	return ParseWho(out), nil
}

// ParseWho parses `who` output run with TZ=UTC and LC_ALL=C.
func ParseWho(out string) []Session {
	res := []Session{}
	for _, line := range lines(out) {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		s := Session{User: f[0], TTY: f[1]}
		if t, err := time.Parse("2006-01-02 15:04", f[2]+" "+f[3]); err == nil {
			s.Since = utcRFC3339(t)
		} else {
			s.Since = f[2] + " " + f[3]
		}
		if len(f) >= 5 && strings.HasPrefix(f[4], "(") {
			s.From = strings.Trim(strings.Join(f[4:], " "), "()")
		}
		res = append(res, s)
	}
	return res
}

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r"); strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
