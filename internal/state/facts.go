package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
)

// OSInfo is the os object in enrollment and heartbeat payloads.
type OSInfo struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

// Facts is the heartbeat facts object.
type Facts struct {
	Hostname       string `json:"hostname"`
	OS             OSInfo `json:"os"`
	Kernel         string `json:"kernel"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	PackageManager string `json:"package_manager"`
}

// ParseOSRelease parses os-release(5) content.
func ParseOSRelease(s string) map[string]string {
	out := map[string]string{}
	for _, line := range lines(s) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
			v = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(v)
		}
		out[k] = v
	}
	return out
}

// OSRelease reads /etc/os-release (or /usr/lib/os-release).
func (e *Env) OSRelease() (map[string]string, error) {
	s, err := e.readFile("/etc/os-release")
	if err != nil {
		s, err = e.readFile("/usr/lib/os-release")
		if err != nil {
			return nil, fmt.Errorf("os-release: %w", err)
		}
	}
	return ParseOSRelease(s), nil
}

// OSInfo returns the os object.
func (e *Env) OSInfo() (OSInfo, error) {
	r, err := e.OSRelease()
	if err != nil {
		return OSInfo{}, err
	}
	return OSInfo{ID: r["ID"], VersionID: r["VERSION_ID"], PrettyName: r["PRETTY_NAME"]}, nil
}

// MachineID reads /etc/machine-id.
func (e *Env) MachineID() (string, error) {
	s, err := e.readFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(s)
	if id == "" {
		return "", fmt.Errorf("machine-id is empty")
	}
	return id, nil
}

// Kernel reads the running kernel release.
func (e *Env) Kernel() (string, error) {
	s, err := e.readFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(s), err
}

// Uptime reads whole seconds of uptime.
func (e *Env) Uptime() (int64, error) {
	s, err := e.readFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, fmt.Errorf("uptime: empty")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return int64(v), err
}

// Facts gathers the heartbeat facts. Missing pieces are left empty.
func (e *Env) Facts() Facts {
	f := Facts{PackageManager: e.PackageManager}
	if e.Hostname != nil {
		f.Hostname, _ = e.Hostname()
	}
	f.OS, _ = e.OSInfo()
	f.Kernel, _ = e.Kernel()
	f.UptimeSeconds, _ = e.Uptime()
	return f
}

// DetectPackageManager picks apt or dnf from os-release, falling back to
// which binary exists. It returns "" if neither fits.
func (e *Env) DetectPackageManager() string {
	if r, err := e.OSRelease(); err == nil {
		ids := strings.Fields(r["ID"] + " " + r["ID_LIKE"])
		for _, id := range ids {
			switch id {
			case "debian", "ubuntu":
				return catalog.PackageManagerApt
			case "rhel", "fedora", "centos":
				return catalog.PackageManagerDnf
			}
		}
	}
	if _, err := os.Stat(e.Path("/usr/bin/apt-get")); err == nil {
		return catalog.PackageManagerApt
	}
	if _, err := os.Stat(e.Path("/usr/bin/dnf")); err == nil {
		return catalog.PackageManagerDnf
	}
	return ""
}
