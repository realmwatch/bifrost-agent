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
