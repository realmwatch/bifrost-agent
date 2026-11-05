// Package testkit builds signed envelopes and approvals for tests of the
// packages that sit on top of verification.
package testkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/realmwatch/bifrost-agent/internal/verify"
)

// Test identities.
const (
	MachineID = "0123456789abcdef0123456789abcdef"
	RPID      = "approve.example.com"
	Origin    = "https://approve.example.com"
)

// Approver holds one ES256 passkey.
type Approver struct {
	KeyID string
	Owner string
	priv  *ecdsa.PrivateKey
}

// NewApprover generates a passkey for owner.
func NewApprover(owner string) *Approver {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Approver{KeyID: verify.B64U([]byte("cred-" + owner)), Owner: owner, priv: k}
}

// Spare generates another passkey for the same owner, as a person with a
// phone and a hardware key has.
func (a *Approver) Spare(name string) *Approver {
	s := NewApprover(a.Owner)
	s.KeyID = verify.B64U([]byte("cred-" + a.Owner + "-" + name))
	return s
}

// Entry renders the approver's passkey as a key set entry.
func (a *Approver) Entry() map[string]any {
	spki, err := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"kind": "passkey", "key_id": a.KeyID, "owner": a.Owner, "label": "test", "alg": verify.AlgES256,
		"public_key": verify.B64U(spki), "rp_id": RPID, "origin": Origin,
	}
}

// TrustedKeysJSON renders a legacy {"v": 1, "keys": [...]} trusted keys
// file for the approvers.
func TrustedKeysJSON(approvers ...*Approver) []byte {
	keys := []map[string]any{}
	for _, a := range approvers {
		keys = append(keys, a.Entry())
	}
	b, _ := json.Marshal(map[string]any{"v": 1, "keys": keys})
	return b
}

// OrganizationID is the organization of KeySet documents.
const OrganizationID = "01JORG"

// KeySet renders a key set document for organization OrganizationID.
func KeySet(serial, threshold int, approvers ...*Approver) []byte {
	keys := []map[string]any{}
	for _, a := range approvers {
		keys = append(keys, a.Entry())
	}
	return KeySetWith(map[string]any{"serial": serial, "update_threshold": threshold, "keys": keys})
}

// KeySetWith renders a key set document from defaults overridden by
// fields; a nil value removes the field.
func KeySetWith(fields map[string]any) []byte {
	m := map[string]any{
		"v": 1, "kind": verify.KeySetKind, "organization_id": OrganizationID, "serial": 1,
		"update_threshold": 1, "issued_at": "2026-11-05T00:00:00Z", "keys": []any{},
	}
	for k, v := range fields {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// Update signs a key set with each approver, as GET /work delivers it.
func Update(keySet []byte, approvers ...*Approver) verify.KeySetUpdate {
	u := verify.KeySetUpdate{KeySet: verify.B64U(keySet), Approvals: []verify.Approval{}}
	for _, a := range approvers {
		u.Approvals = append(u.Approvals, a.Approve(keySet))
	}
	return u
}

// TrustedKeys parses TrustedKeysJSON.
func TrustedKeys(approvers ...*Approver) *verify.TrustedKeys {
	k, err := verify.ParseTrustedKeys(TrustedKeysJSON(approvers...))
	if err != nil {
		panic(err)
	}
	return k
}

// Approve signs a WebAuthn assertion over envelope or key set bytes.
func (a *Approver) Approve(envelope []byte) verify.Approval {
	hash := sha256.Sum256(envelope)
	cdj, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": verify.B64U(hash[:]), "origin": Origin})
	rp := sha256.Sum256([]byte(RPID))
	authData := append(rp[:], 0x05, 0, 0, 0, 1)
	cdHash := sha256.Sum256(cdj)
	d := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, d[:])
	if err != nil {
		panic(err)
	}
	return verify.Approval{Kind: "passkey", KeyID: a.KeyID, AuthenticatorData: verify.B64U(authData),
		ClientDataJSON: verify.B64U(cdj), Signature: verify.B64U(sig)}
}

// Step is an envelope operation.
type Step struct {
	Op      string
	Version int
	Params  map[string]any
}

// Envelope renders envelope bytes for MachineID, expiring at expires
// (RFC 3339), with a nonce derived from seed.
func Envelope(ops, rollback []Step, expires string, seed int) []byte {
	conv := func(steps []Step) []any {
		out := []any{}
		for _, s := range steps {
			out = append(out, map[string]any{"op": s.Op, "version": s.Version, "params": s.Params})
		}
		return out
	}
	b, err := json.Marshal(map[string]any{
		"v": 1, "kind": "bifrost.envelope", "proposal_id": "01JPROPOSAL", "organization_id": "01JORG",
		"hosts":      []any{map[string]any{"server_id": "01JSERVER", "name": "web-01", "machine_id": MachineID}},
		"operations": conv(ops), "rollback": conv(rollback), "irreversible": false,
		"intent": "test", "risk_tier": "low", "not_before": nil, "expires_at": expires,
		"nonce": fmt.Sprintf("%064x", seed),
	})
	if err != nil {
		panic(err)
	}
	return b
}
