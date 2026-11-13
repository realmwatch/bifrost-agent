package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxBatchEnvelopes is the most envelopes one batch may list.
const MaxBatchEnvelopes = 100

// BatchList lists the steps a passkey_batch approval may approve: every
// operation must be in Operations and every rollback step in Rollback.
type BatchList struct {
	Operations []string
	Rollback   []string
}

// CompiledBatchApproval is the agent's own batch list: routine fleet upkeep
// (package updates, agent and collector upgrades, package list refreshes,
// holds, service restarts and reloads, old kernel removal and reboots) and
// nothing else, whatever the hub puts in it. The hub staggers the reboots
// in a batch; each agent only checks its own envelope.
var CompiledBatchApproval = BatchList{
	Operations: []string{
		"package.upgrade@1", "packages.upgrade@1",
		"agent.upgrade@1", "collector.upgrade@1",
		"package.refresh@1", "package.hold@1", "package.unhold@1",
		"service.restart@1", "service.reload@1",
		"kernel.remove@1", "system.reboot@1",
	},
	Rollback: []string{"package.install@1", "package.hold@1", "package.unhold@1"},
}

// allows reports why env is not batchable, or nil when it is.
func (l BatchList) allows(env *Envelope) error {
	for _, s := range env.Operations {
		if !contains(l.Operations, s.Key()) {
			return fmt.Errorf("operation %s can't be approved in a batch", s.Key())
		}
	}
	for _, s := range env.Rollback {
		if !contains(l.Rollback, s.Key()) {
			return fmt.Errorf("rollback step %s can't be approved in a batch", s.Key())
		}
	}
	return nil
}

// Batch is a signed list of envelope hashes, parsed from its exact bytes.
type Batch struct {
	V              int      `json:"v"`
	Kind           string   `json:"kind"`
	OrganizationID string   `json:"organization_id"`
	Envelopes      []string `json:"envelopes"`

	// Hash is SHA-256 of the batch bytes, the passkey's challenge.
	Hash [32]byte `json:"-"`
}

// ParseBatch parses batch bytes as strictly as an envelope.
func ParseBatch(data []byte) (*Batch, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var b Batch
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	if b.V != 1 {
		return nil, fmt.Errorf("unsupported batch version %d", b.V)
	}
	if b.Kind != "bifrost.batch" {
		return nil, fmt.Errorf("kind is %q, want bifrost.batch", b.Kind)
	}
	if b.OrganizationID == "" {
		return nil, errors.New("no organization_id")
	}
	if n := len(b.Envelopes); n < 1 || n > MaxBatchEnvelopes {
		return nil, fmt.Errorf("%d envelopes, want 1 to %d", n, MaxBatchEnvelopes)
	}
	seen := map[string]bool{}
	for i, h := range b.Envelopes {
		if !nonceRe.MatchString(h) {
			return nil, fmt.Errorf("envelopes[%d] is not 64 lowercase hex characters", i)
		}
		if seen[h] {
			return nil, fmt.Errorf("envelopes[%d] is listed twice", i)
		}
		seen[h] = true
	}
	b.Hash = sha256.Sum256(data)
	return &b, nil
}

// VerifyBatch checks a passkey_batch approval for env against a trusted
// key and the batch list, in the order PROTOCOL.md lists the batch checks.
func VerifyBatch(k *TrustedKey, a Approval, env *Envelope, list BatchList) error {
	raw, err := DecodeB64U(a.Batch)
	if err != nil {
		return fmt.Errorf("batch: %w", err)
	}
	b, err := ParseBatch(raw)
	if err != nil {
		return fmt.Errorf("bad batch: %w", err)
	}
	if b.OrganizationID != env.OrganizationID {
		return fmt.Errorf("batch organization_id %q is not the envelope's", b.OrganizationID)
	}
	if !contains(b.Envelopes, hex.EncodeToString(env.Hash[:])) {
		return errors.New("envelope is not in the batch")
	}
	if err := VerifyPasskey(k, a, b.Hash); err != nil {
		return err
	}
	return list.allows(env)
}
