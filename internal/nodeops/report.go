package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/realmwatch/bifrost-agent/internal/redact"
)

const (
	maxUses     = 500
	maxLineSize = 300
)

// Report is what `node report` prints, for the node_installs state tool.
type Report struct {
	Default  *DefaultNodeInfo `json:"default"`
	Installs []Install        `json:"installs"`
	Uses     []Use            `json:"uses"`
}

// DefaultNodeInfo is /usr/bin/node. Source is "nodesource" when NodeSource's
// nodejs package installed it, "other" for another package, "" when no
// package did.
type DefaultNodeInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Major   string `json:"major"`
	Source  string `json:"source"`
}

// Install is one side install under /opt/node.
type Install struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Major   string `json:"major"`
}

// Use is one supervisor, systemd or cron line that runs node.
type Use struct {
	Kind   string `json:"kind"`
	File   string `json:"file"`
	Name   string `json:"name"`
	Binary string `json:"binary"`
	Line   string `json:"line"`
}

// Report lists the host's Node.js: the default, the side installs and the
// lines that run node.
func (e *Env) Report(ctx context.Context) (*Report, error) {
	if err := e.checkHost(); err != nil {
		return nil, err
	}
	r := &Report{Installs: []Install{}, Uses: []Use{}}
	if info, err := os.Stat(e.path(DefaultNode)); err == nil && !info.IsDir() {
		d := &DefaultNodeInfo{Path: DefaultNode}
		if v, err := e.nodeVersion(ctx, e.path(DefaultNode)); err == nil {
			d.Version, d.Major = v, majorOf(v)
		}
		pkg, err := e.nodejsVersion(ctx)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.Contains(pkg, "nodesource"):
			d.Source = "nodesource"
		case pkg != "":
			d.Source = "other"
		}
		r.Default = d
	}

	dirs, _ := filepath.Glob(e.path(InstallRoot + "/[0-9][0-9]"))
	sort.Strings(dirs)
	for _, d := range dirs {
		info, err := os.Lstat(d)
		if err != nil || !info.IsDir() {
			continue
		}
		in := Install{Path: e.host(d), Major: filepath.Base(d)}
		if v, err := e.headerVersion(d); err == nil {
			in.Version = v
		}
		r.Installs = append(r.Installs, in)
	}

	for _, s := range e.services() {
		for i := s.start; i <= s.end && len(r.Uses) < maxUses; i++ {
			if !s.cmdLine(i) {
				continue
			}
			for _, b := range binaries(s.lines[i]) {
				if len(r.Uses) == maxUses {
					break
				}
				r.Uses = append(r.Uses, Use{Kind: s.kind, File: s.path, Name: s.name, Binary: b, Line: clip(redact.String(strings.TrimSpace(s.lines[i])))})
			}
		}
	}
	return r, nil
}

// clip cuts s to maxLineSize bytes on a character boundary.
func clip(s string) string {
	if len(s) <= maxLineSize {
		return s
	}
	s = s[:maxLineSize]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
