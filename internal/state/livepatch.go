package state

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// LivepatchClient is Canonical's Livepatch client, installed as a snap.
const LivepatchClient = "/snap/bin/canonical-livepatch"

// Livepatch is what the kernel says about live patches. It's nil where
// the kernel can't take them (no /sys/kernel/livepatch).
type Livepatch struct {
	// Applied is true when a patch is loaded, enabled and not mid-way
	// through being applied.
	Applied bool `json:"applied"`
	// Patches are the loaded patch modules, by name.
	Patches []string `json:"patches"`
}

// Livepatch reads /sys/kernel/livepatch, which needs no privileges and
// runs nothing, so it's cheap enough for every heartbeat.
func (e *Env) Livepatch() *Livepatch {
	dir := e.Path("/sys/kernel/livepatch")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := &Livepatch{Patches: []string{}}
	for _, entry := range entries {
		name := entry.Name()
		enabled, err := os.ReadFile(filepath.Join(dir, name, "enabled"))
		if err != nil {
			continue
		}
		out.Patches = append(out.Patches, name)
		transition, _ := os.ReadFile(filepath.Join(dir, name, "transition"))
		if strings.TrimSpace(string(enabled)) == "1" && strings.TrimSpace(string(transition)) != "1" {
			out.Applied = true
		}
	}
	sort.Strings(out.Patches)
	return out
}

// LivepatchStatus is the running kernel's entry in Canonical's client
// status, for the boot tool.
type LivepatchStatus struct {
	// PatchState is the client's word for it: "applied",
	// "nothing-to-apply", "apply-failed" and so on.
	PatchState string `json:"patch_state"`
	// Version is the patch version, empty when none is applied.
	Version string `json:"version"`
	// Fixes are the CVEs the applied patch fixes, upper case.
	Fixes []string `json:"fixes"`
	// Support is whether Canonical still patches this kernel:
	// "supported", "unsupported", "kernel-upgrade-required" and so on.
	Support string `json:"support"`
	// UpgradeRequiredBy is the date patches for this kernel end, when the
	// client says.
	UpgradeRequiredBy string `json:"upgrade_required_by,omitempty"`
	// Error is why the client couldn't say, when it couldn't.
	Error string `json:"error,omitempty"`
}

var cveRe = regexp.MustCompile(`(?i)\bcve-\d{4}-\d{4,}\b`)

// LivepatchStatus asks Canonical's client about the running kernel. It's
// nil when the client isn't installed. The client's JSON isn't a stable
// interface, so the fields are read by their known names and anything
// missing is left empty.
func (e *Env) LivepatchStatus(ctx context.Context) *LivepatchStatus {
	if _, err := os.Stat(e.Path(LivepatchClient)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	stdout, code, err := e.run(ctx, LivepatchClient, "status", "--format", "json")
	if err != nil || code != 0 {
		msg := "canonical-livepatch status failed"
		if err != nil {
			msg += ": " + err.Error()
		}
		return &LivepatchStatus{Fixes: []string{}, Error: msg}
	}
	var doc struct {
		Status []map[string]any `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return &LivepatchStatus{Fixes: []string{}, Error: "canonical-livepatch status isn't JSON"}
	}
	out := &LivepatchStatus{Fixes: []string{}}
	var entry map[string]any
	for _, s := range doc.Status {
		if running, _ := s["running"].(bool); running || entry == nil {
			entry = s
		}
	}
	if entry == nil {
		out.Error = "canonical-livepatch status lists no kernel"
		return out
	}
	out.Support = firstString(entry, "supported", "support")
	out.UpgradeRequiredBy = firstString(entry, "upgradeRequiredDate", "upgrade-required-date", "upgrade_required_date")
	lp, _ := entry["livepatch"].(map[string]any)
	if lp == nil {
		return out
	}
	out.PatchState = firstString(lp, "patchState", "patch-state", "state")
	out.Version = firstString(lp, "version")
	seen := map[string]bool{}
	var texts []string
	switch fixes := lp["fixes"].(type) {
	case string:
		texts = append(texts, fixes)
	case []any:
		for _, f := range fixes {
			b, _ := json.Marshal(f)
			texts = append(texts, string(b))
		}
	}
	for _, t := range texts {
		for _, cve := range cveRe.FindAllString(t, -1) {
			cve = strings.ToUpper(cve)
			if !seen[cve] {
				seen[cve] = true
				out.Fixes = append(out.Fixes, cve)
			}
		}
	}
	sort.Strings(out.Fixes)
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}
