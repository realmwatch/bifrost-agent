package state

import (
	"regexp"
	"strings"
)

// collectorPath is where Heimdall's installer puts the collector.
const collectorPath = "/usr/local/bin/heimdall-collect"

var collectorVersionLine = regexp.MustCompile(`^VERSION=([0-9]+\.[0-9]+\.[0-9]+)$`)

// CollectorVersion reads the installed Heimdall collector's version from its
// script, without running it. It's "" when there's no collector.
func (e *Env) CollectorVersion() string {
	script, err := e.readFile(collectorPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(script, "\n") {
		if m := collectorVersionLine.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

// collectorEnvPaths are where Heimdall's installer writes the collector's
// settings, the first readable one winning (as the collector reads them).
var collectorEnvPaths = []string{"/etc/heimdall/collect.env", "/etc/heimdall-collect/collect.env"}

// collectorSettings maps a collect.env setting to the name the hub sees.
var collectorSettings = map[string]string{
	"HEIMDALL_PRIVILEGE_WATCH": "privilege_watch",
	"HEIMDALL_LOGIN_WATCH":     "login_watch",
	"HEIMDALL_TRIPWIRES":       "tripwires",
}

var collectorSettingValue = regexp.MustCompile(`^(on|off|users)$`)

// CollectorSettings reports which optional collector reports are on, from
// collect.env (world-readable, without running it): privilege_watch is on,
// users or off, and login_watch and tripwires are on or off. A setting the
// file doesn't have is off, as the collector treats it. It's nil when there
// is no collector or no settings file.
func (e *Env) CollectorSettings() map[string]string {
	if e.CollectorVersion() == "" {
		return nil
	}
	for _, path := range collectorEnvPaths {
		env, err := e.readFile(path)
		if err != nil {
			continue
		}
		out := map[string]string{}
		for _, name := range collectorSettings {
			out[name] = "off"
		}
		for _, line := range strings.Split(env, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			name, known := collectorSettings[k]
			if !ok || !known {
				continue
			}
			v = strings.Trim(v, `'"`)
			if collectorSettingValue.MatchString(v) && (v != "users" || name == "privilege_watch") {
				out[name] = v
			}
		}
		return out
	}
	return nil
}
