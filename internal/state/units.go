package state

import (
	"context"
	"sort"
	"strings"
)

// FailedUnits lists the failed systemd services, leaving out oneshot ones:
// those are usually run by a timer and fail on their own schedule, not
// because of a change. Reading unit states needs no privileges.
func (e *Env) FailedUnits(ctx context.Context) ([]string, error) {
	out, err := e.runOK(ctx, "systemctl", "list-units", "--state=failed", "--type=service", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	var failed []string
	for _, unit := range ParseFailedUnits(out) {
		kind, err := e.runOK(ctx, "systemctl", "show", "-p", "Type", "--value", unit)
		if err == nil && strings.TrimSpace(kind) == "oneshot" {
			continue
		}
		failed = append(failed, unit)
	}
	return failed, nil
}

// ParseFailedUnits reads the unit names from `systemctl list-units --plain
// --no-legend`: the first field of each line, when it names a service.
func ParseFailedUnits(out string) []string {
	seen := map[string]bool{}
	var units []string
	for _, line := range lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := strings.TrimLeft(fields[0], "●* ")
		if unit == "" && len(fields) > 1 {
			unit = fields[1]
		}
		if !strings.HasSuffix(unit, ".service") || seen[unit] {
			continue
		}
		seen[unit] = true
		units = append(units, unit)
	}
	sort.Strings(units)
	return units
}
