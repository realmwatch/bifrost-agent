// Package verify implements the checks the agent runs on an envelope and its
// approvals before running anything, in the order PROTOCOL.md lists them.
package verify

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/nonce"
)

// DenyRule is a hard rule compiled into the agent. Match returns a reason
// when the step must not run.
type DenyRule struct {
	Name  string
	Match func(def *catalog.Definition, params map[string]any) (reason string, denied bool)
}

// CompiledDenyRules are the agent's own deny rules. None yet: the hook is
// in place and tested.
var CompiledDenyRules = []DenyRule{}

// CompiledAutoApproval lists the operations a policy approval alone may
// approve. Certificate renewal and security updates join when they exist.
var CompiledAutoApproval = []string{"service.restart@1"}

// Check numbers, as in PROTOCOL.md.
const (
	CheckParse     = 1
	CheckHost      = 2
	CheckTime      = 3
	CheckNonce     = 4
	CheckOperation = 5
	CheckDeny      = 6
	CheckApproval  = 7
)

// Rejection is a failed check. Reason is what the rejected event carries.
type Rejection struct {
	Check  int
	Reason string
	// Detail adds context for logs; it is not sent to the hub.
	Detail string
}

func (r *Rejection) Error() string {
	if r.Detail != "" {
		return fmt.Sprintf("check %d: %s (%s)", r.Check, r.Reason, r.Detail)
	}
	return fmt.Sprintf("check %d: %s", r.Check, r.Reason)
}

func reject(check int, reason string, args ...any) *Rejection {
	return &Rejection{Check: check, Reason: fmt.Sprintf(reason, args...)}
}

// Verifier holds what the checks need.
type Verifier struct {
	Catalog *catalog.Catalog
	Keys    *TrustedKeys
	// MachineID is this host's /etc/machine-id.
	MachineID string
	// PackageManager selects the argument lists steps must have.
	PackageManager string
	Nonces         *nonce.Store
	Now            func() time.Time
	DenyRules      []DenyRule
	// AutoApprove holds name@version keys; nil means CompiledAutoApproval.
	AutoApprove []string
}

// Result describes an envelope that passed every check.
type Result struct {
	Envelope *Envelope
	// Tier is the highest compiled min_tier of every step.
	Tier catalog.Tier
	// Owners are the distinct owners of valid passkey approvals.
	Owners []string
	// PolicyOnly is true when a policy approval alone approved it.
	PolicyOnly bool
	// Ignored lists approvals that did not verify, for logs.
	Ignored []string
}

var nonceRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Verify runs checks 1 to 7. It does not record the nonce; see Consume.
func (v *Verifier) Verify(raw []byte, approvals []Approval) (*Result, error) {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now()

	// 1. The envelope parses.
	env, err := ParseEnvelope(raw)
	if err != nil {
		if errors.Is(err, ErrDuplicateKey) {
			return nil, &Rejection{Check: CheckParse, Reason: "duplicate JSON key", Detail: err.Error()}
		}
		return nil, reject(CheckParse, "bad envelope: %v", err)
	}

	// 2. This host is in hosts.
	found := false
	for _, h := range env.Hosts {
		if v.MachineID != "" && h.MachineID == v.MachineID {
			found = true
		}
	}
	if !found {
		return nil, reject(CheckHost, "wrong host: this machine is not in the envelope's hosts")
	}

	// 3. Time window.
	if !env.NotBeforeTime.IsZero() && t.Before(env.NotBeforeTime) {
		return nil, reject(CheckTime, "not yet valid: not_before is %s", env.NotBeforeTime.UTC().Format(time.RFC3339))
	}
	if !t.Before(env.ExpiresAtTime) {
		return nil, reject(CheckTime, "expired at %s", env.ExpiresAtTime.UTC().Format(time.RFC3339))
	}

	// 4. Nonce not seen.
	if !nonceRe.MatchString(env.Nonce) {
		return nil, reject(CheckNonce, "bad nonce: want 32 bytes as lowercase hex")
	}
	if v.Nonces == nil {
		return nil, reject(CheckNonce, "no nonce store")
	}
	if v.Nonces.Seen(env.Nonce) {
		return nil, reject(CheckNonce, "replayed nonce")
	}

	// 5. Every step is compiled in and its params match.
	type checked struct {
		def  *catalog.Definition
		step Step
	}
	var steps []checked
	tier := catalog.TierLow
	for _, group := range []struct {
		name  string
		steps []Step
	}{{"operations", env.Operations}, {"rollback", env.Rollback}} {
		for i, s := range group.steps {
			def, ok := v.Catalog.Get(s.Op, s.Version)
			if !ok {
				return nil, reject(CheckOperation, "unknown operation %s", s.Key())
			}
			if !def.Supports(v.PackageManager) {
				return nil, reject(CheckOperation, "operation %s is not supported with package manager %q", s.Key(), v.PackageManager)
			}
			if err := def.Params.Validate(s.Params); err != nil {
				return nil, reject(CheckOperation, "bad params for %s[%d] %s: %v", group.name, i, s.Key(), err)
			}
			if def.MinTier > tier {
				tier = def.MinTier
			}
			steps = append(steps, checked{def, s})
		}
	}

	// 6. Deny rules.
	for _, c := range steps {
		for _, rule := range v.DenyRules {
			if reason, denied := rule.Match(c.def, c.step.Params); denied {
				return nil, reject(CheckDeny, "denied by agent rule %s: %s", rule.Name, reason)
			}
		}
	}

	// 7. Approvals, with the compiled tier.
	res := &Result{Envelope: env, Tier: tier}
	if v.Keys == nil {
		return nil, reject(CheckApproval, "no trusted keys")
	}
	owners := map[string]bool{}
	policyOK := false
	for i, a := range approvals {
		var err error
		switch a.Kind {
		case "passkey":
			k, ok := v.Keys.Passkey(a.KeyID)
			if !ok {
				err = errors.New("untrusted passkey")
			} else if err = VerifyPasskey(k, a, env.Hash); err == nil {
				owners[k.Owner] = true
			}
		case "policy":
			k, ok := v.Keys.Policy(a.KeyID)
			if !ok {
				err = errors.New("untrusted policy key")
			} else if err = VerifyPolicy(k, a, env.Raw); err == nil {
				policyOK = true
			}
		default:
			err = fmt.Errorf("unknown kind %q", a.Kind)
		}
		if err != nil {
			res.Ignored = append(res.Ignored, fmt.Sprintf("approval %d (%s %s): %v", i, a.Kind, a.KeyID, err))
		}
	}
	for o := range owners {
		res.Owners = append(res.Owners, o)
	}
	sort.Strings(res.Owners)
	detail := strings.Join(res.Ignored, "; ")

	switch {
	case len(owners) > 0:
		if tier == catalog.TierCritical && len(owners) < 2 {
			r := reject(CheckApproval, "critical operations need passkey approvals from two different owners")
			r.Detail = detail
			return nil, r
		}
	case policyOK:
		auto := v.AutoApprove
		if auto == nil {
			auto = CompiledAutoApproval
		}
		for _, c := range steps {
			if !contains(auto, c.def.Key()) {
				r := reject(CheckApproval, "a policy approval alone cannot approve %s", c.def.Key())
				r.Detail = detail
				return nil, r
			}
		}
		res.PolicyOnly = true
	default:
		r := reject(CheckApproval, "no valid passkey approval from a trusted key")
		r.Detail = detail
		return nil, r
	}
	return res, nil
}

// Consume records the envelope's nonce, so it cannot run again. Call it
// after Verify succeeds and before running anything.
func (v *Verifier) Consume(env *Envelope) error {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if err := v.Nonces.Add(env.Nonce, env.ExpiresAtTime, now()); err != nil {
		if errors.Is(err, nonce.ErrSeen) {
			return reject(CheckNonce, "replayed nonce")
		}
		return &Rejection{Check: CheckNonce, Reason: "could not record the nonce", Detail: err.Error()}
	}
	return nil
}

// VerifyAndConsume is Verify followed by Consume.
func (v *Verifier) VerifyAndConsume(raw []byte, approvals []Approval) (*Result, error) {
	res, err := v.Verify(raw, approvals)
	if err != nil {
		return nil, err
	}
	if err := v.Consume(res.Envelope); err != nil {
		return nil, err
	}
	return res, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
