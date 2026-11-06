package state

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
)

// AgentUnit is the agent's own systemd unit.
const AgentUnit = catalog.AgentUnit

// BootID reads the kernel's random boot ID, which changes on every boot.
func (e *Env) BootID() (string, error) {
	s, err := e.readFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(s)
	if id == "" {
		return "", fmt.Errorf("boot_id is empty")
	}
	return id, nil
}

// ScheduledShutdown is a shutdown or reboot systemd has scheduled.
type ScheduledShutdown struct {
	// Mode is "reboot", "poweroff", "halt" and so on.
	Mode string `json:"mode"`
	// At is when it happens, RFC 3339 in UTC; empty if unknown.
	At string `json:"at"`
}

// ScheduledShutdown reads /run/systemd/shutdown/scheduled, which systemd
// writes for `shutdown -r +N`. It returns nil if nothing is scheduled.
func (e *Env) ScheduledShutdown() (*ScheduledShutdown, error) {
	s, err := e.readFile("/run/systemd/shutdown/scheduled")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &ScheduledShutdown{}
	for _, line := range lines(s) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "MODE":
			out.Mode = v
		case "USEC":
			if usec, err := strconv.ParseInt(v, 10, 64); err == nil {
				out.At = utcRFC3339(time.UnixMicro(usec))
			}
		}
	}
	return out, nil
}

// RebootRequired reports whether installed updates (a new kernel, libc,
// microcode) need a reboot, and which packages say so where the system
// records it. known is false if this system can't tell.
func (e *Env) RebootRequired(ctx context.Context) (required bool, packages []string, known bool) {
	packages = []string{}
	switch e.PackageManager {
	case catalog.PackageManagerApt:
		if _, err := os.Stat(e.Path("/run/reboot-required")); err != nil {
			return false, packages, errors.Is(err, fs.ErrNotExist)
		}
		if s, err := e.readFile("/run/reboot-required.pkgs"); err == nil {
			seen := map[string]bool{}
			for _, p := range lines(s) {
				if !seen[p] {
					seen[p] = true
					packages = append(packages, p)
				}
			}
		}
		return true, packages, true
	case catalog.PackageManagerDnf:
		// Exit 1 means a reboot is needed, 0 that it isn't.
		_, code, err := e.run(ctx, "dnf", "-q", "needs-restarting", "-r")
		if err != nil || (code != 0 && code != 1) {
			return false, packages, false
		}
		return code == 1, packages, true
	}
	return false, packages, false
}

func toolBoot(ctx context.Context, e *Env, _ map[string]any) (any, error) {
	id, err := e.BootID()
	if err != nil {
		return nil, err
	}
	res := map[string]any{"boot_id": id}
	res["uptime_seconds"], _ = e.Uptime()
	res["kernel"], _ = e.Kernel()
	required, packages, known := e.RebootRequired(ctx)
	if known {
		res["reboot_required"] = required
	} else {
		res["reboot_required"] = nil
	}
	res["reboot_required_by"] = packages
	scheduled, err := e.ScheduledShutdown()
	if err != nil {
		return nil, err
	}
	res["scheduled_shutdown"] = scheduled
	return res, nil
}

// privileged prefixes a read-only command with sudo when the agent runs
// operations through sudo.
func (e *Env) privileged(argv []string) []string {
	if !e.UseSudo {
		return argv
	}
	return append(append([]string{}, catalog.SudoArgv...), argv...)
}

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]*$`)

func toolServicesNeedingRestart(ctx context.Context, e *Env, _ map[string]any) (any, error) {
	if err := e.requirePM(); err != nil {
		return nil, err
	}
	argv := catalog.PrivilegedReads["services_needing_restart"][e.PackageManager]
	if e.PackageManager == catalog.PackageManagerApt {
		if _, err := os.Stat(e.Path(argv[0])); err != nil {
			return nil, fmt.Errorf("needrestart is not installed")
		}
	}
	out, err := e.runOK(ctx, e.privileged(argv)...)
	if err != nil {
		return nil, err
	}
	if e.PackageManager == catalog.PackageManagerApt {
		return map[string]any{"services": ParseNeedrestart(out)}, nil
	}
	return map[string]any{"services": ParseNeedsRestartingServices(out)}, nil
}

// ParseNeedrestart parses `needrestart -b` (batch mode) into the services
// that still use old copies of upgraded libraries.
func ParseNeedrestart(out string) []string {
	services := []string{}
	for _, line := range lines(out) {
		name, ok := strings.CutPrefix(line, "NEEDRESTART-SVC:")
		if name = strings.TrimSpace(name); ok && serviceNameRe.MatchString(name) {
			services = append(services, name)
		}
	}
	return services
}

// ParseNeedsRestartingServices parses `dnf needs-restarting -s`: one
// service per line.
func ParseNeedsRestartingServices(out string) []string {
	services := []string{}
	for _, line := range lines(out) {
		name := strings.TrimSpace(line)
		if !serviceNameRe.MatchString(name) {
			continue
		}
		if !strings.Contains(name, ".") {
			name += ".service"
		}
		services = append(services, name)
	}
	return services
}

// HeldPackages returns the packages held at their version: `apt-mark
// showhold`, or dnf's versionlock list. Without the dnf versionlock plugin
// nothing is held.
func (e *Env) HeldPackages(ctx context.Context) (map[string]bool, error) {
	held := map[string]bool{}
	switch e.PackageManager {
	case catalog.PackageManagerApt:
		out, err := e.runOK(ctx, "apt-mark", "showhold")
		if err != nil {
			return nil, err
		}
		for _, name := range lines(out) {
			held[strings.TrimSpace(name)] = true
		}
	case catalog.PackageManagerDnf:
		out, code, err := e.run(ctx, "dnf", "-q", "versionlock", "list")
		if err != nil || code != 0 {
			return held, nil
		}
		for name := range ParseDnfVersionlock(out) {
			held[name] = true
		}
	default:
		return nil, errNoPackageManager
	}
	return held, nil
}

// ParseDnfVersionlock parses `dnf versionlock list` entries such as
// "nginx-1:1.20.1-14.el9.*" into package names.
func ParseDnfVersionlock(out string) map[string]bool {
	names := map[string]bool{}
	for _, line := range lines(out) {
		f := strings.Fields(line)
		if len(f) != 1 || strings.HasSuffix(f[0], ":") {
			continue
		}
		if name := nevraName(strings.TrimPrefix(f[0], "!")); name != "" {
			names[name] = true
		}
	}
	return names
}
