package verify

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// KeySetUpdate is one item of GET /work's keysets, and the content of a
// stored update (state_dir/keysets/<serial>.json).
type KeySetUpdate struct {
	// KeySet is the b64u of the key set bytes.
	KeySet    string     `json:"keyset"`
	Approvals []Approval `json:"approvals"`
}

// Key set update check numbers, as in PROTOCOL.md (Trusted keys, Updates).
const (
	KeySetCheckParse    = 1
	KeySetCheckSerial   = 2
	KeySetCheckOrg      = 3
	KeySetCheckUsable   = 4
	KeySetCheckApproval = 5
)

// ErrKeySetStale reports an update whose serial is not above the current
// one. It is ignored without a log line.
var ErrKeySetStale = errors.New("key set serial is not above the current one")

// ErrKeySetGap reports an update more than one serial ahead: the agent
// waits for the missing one.
var ErrKeySetGap = errors.New("key set serial skips ahead; waiting for the missing update")

// CheckKeySetUpdate runs update checks 1 to 5 on raw (the key set bytes)
// while trusting current, and returns the new key set. Check 2 fails with
// ErrKeySetStale or ErrKeySetGap (wrapped); the others with a *Rejection
// carrying the check number.
func CheckKeySetUpdate(current *TrustedKeys, raw []byte, approvals []Approval) (*TrustedKeys, error) {
	if current == nil {
		return nil, reject(KeySetCheckApproval, "no current key set")
	}

	// 1. It parses strictly.
	next, err := ParseKeySet(raw)
	if err != nil {
		return nil, &Rejection{Check: KeySetCheckParse, Reason: "bad key set", Detail: err.Error()}
	}

	// 2. The serial is the next one.
	switch {
	case next.Serial <= current.Serial:
		return nil, fmt.Errorf("%w (serial %d, current %d)", ErrKeySetStale, next.Serial, current.Serial)
	case next.Serial != current.Serial+1:
		return nil, fmt.Errorf("%w (serial %d, current %d)", ErrKeySetGap, next.Serial, current.Serial)
	}

	// 3. Same organization.
	if current.OrganizationID != "" && next.OrganizationID != current.OrganizationID {
		return nil, reject(KeySetCheckOrg, "organization_id %q is not the current key set's %q", next.OrganizationID, current.OrganizationID)
	}

	// 4. It is usable.
	if err := next.Usable(); err != nil {
		return nil, reject(KeySetCheckUsable, "unusable key set: %v", err)
	}

	// 5. Enough different owners in the current set approved it. Policy keys
	// can't approve a key set.
	owners := map[string]bool{}
	var ignored []string
	for i, a := range approvals {
		var err error
		switch a.Kind {
		case "passkey":
			k, ok := current.Passkey(a.KeyID)
			if !ok {
				err = errors.New("not a passkey in the current key set")
			} else if err = VerifyPasskey(k, a, next.Hash); err == nil {
				owners[k.Owner] = true
			}
		case "policy":
			err = errors.New("policy keys can't approve a key set")
		default:
			err = fmt.Errorf("unknown kind %q", a.Kind)
		}
		if err != nil {
			ignored = append(ignored, fmt.Sprintf("approval %d (%s %s): %v", i, a.Kind, a.KeyID, err))
		}
	}
	// A threshold below 1 (an anchor that isn't usable) still needs one owner.
	need := max(current.UpdateThreshold, 1)
	if len(owners) < need {
		var got []string
		for o := range owners {
			got = append(got, o)
		}
		sort.Strings(got)
		r := reject(KeySetCheckApproval, "approved by %d different owners of the current key set, need %d", len(owners), need)
		r.Detail = strings.Join(append([]string{"owners: " + strings.Join(got, ", ")}, ignored...), "; ")
		return nil, r
	}
	return next, nil
}
