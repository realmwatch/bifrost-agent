package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/testkit"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

func TestParseTrustedKeysForms(t *testing.T) {
	alex, sam := testkit.NewApprover("user:alex"), testkit.NewApprover("user:sam")

	legacy, err := verify.ParseTrustedKeys(testkit.TrustedKeysJSON(alex, alex.Spare("key"), sam))
	if err != nil {
		t.Fatal(err)
	}
	if !legacy.Legacy || legacy.Serial != 0 || legacy.UpdateThreshold != 1 || legacy.OrganizationID != "" ||
		legacy.Len() != 3 || !slices.Equal(legacy.Owners(), []string{"user:alex", "user:sam"}) {
		t.Fatalf("legacy = %+v owners %v", legacy, legacy.Owners())
	}

	set, err := verify.ParseTrustedKeys(testkit.KeySet(3, 2, alex, sam))
	if err != nil {
		t.Fatal(err)
	}
	if set.Legacy || set.Serial != 3 || set.UpdateThreshold != 2 || set.OrganizationID != testkit.OrganizationID ||
		set.IssuedAt.IsZero() || set.Usable() != nil {
		t.Fatalf("key set = %+v", set)
	}

	bad := map[string][]byte{
		"legacy with a serial":  []byte(`{"v":1,"serial":1,"keys":[]}`),
		"wrong kind":            testkit.KeySetWith(map[string]any{"kind": "bifrost.envelope"}),
		"version 2":             testkit.KeySetWith(map[string]any{"v": 2}),
		"serial 0":              testkit.KeySetWith(map[string]any{"serial": 0}),
		"fractional serial":     testkit.KeySetWith(map[string]any{"serial": 1.5}),
		"no organization":       testkit.KeySetWith(map[string]any{"organization_id": nil}),
		"bad issued_at":         testkit.KeySetWith(map[string]any{"issued_at": "yesterday"}),
		"unknown field":         testkit.KeySetWith(map[string]any{"extra": true}),
		"duplicate json key":    []byte(`{"v":1,"kind":"bifrost.keyset","kind":"bifrost.keyset"}`),
		"passkey and policy id": testkit.KeySetWith(map[string]any{"keys": []any{alex.Entry(), map[string]any{"kind": "policy", "key_id": alex.KeyID, "public_key": verify.B64U(make([]byte, 32))}}}),
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := verify.ParseTrustedKeys(doc); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCheckKeySetUpdate(t *testing.T) {
	alex, sam, kim := testkit.NewApprover("user:alex"), testkit.NewApprover("user:sam"), testkit.NewApprover("user:kim")
	alexSpare := alex.Spare("hardware-key")
	eve := testkit.NewApprover("user:eve")
	_, policyPriv, _ := ed25519.GenerateKey(rand.Reader)
	policyEntry := map[string]any{"kind": "policy", "key_id": "policy-1", "public_key": verify.B64U(policyPriv.Public().(ed25519.PublicKey))}

	// The current set: serial 4, three owners (alex with a spare), threshold 2,
	// and a policy key.
	current, err := verify.ParseTrustedKeys(testkit.KeySetWith(map[string]any{
		"serial": 4, "update_threshold": 2,
		"keys": []any{alex.Entry(), alexSpare.Entry(), sam.Entry(), kim.Entry(), policyEntry},
	}))
	if err != nil {
		t.Fatal(err)
	}
	next := testkit.KeySet(5, 2, alex, sam)
	policySig := verify.Approval{Kind: "policy", KeyID: "policy-1", Signature: verify.B64U(ed25519.Sign(policyPriv, next))}
	approvals := func(doc []byte, as ...*testkit.Approver) []verify.Approval {
		return testkit.Update(doc, as...).Approvals
	}
	withKeys := func(fields map[string]any) []byte {
		fields["serial"] = 5
		if _, ok := fields["keys"]; !ok {
			fields["keys"] = []any{alex.Entry(), sam.Entry()}
		}
		return testkit.KeySetWith(fields)
	}

	cases := []struct {
		name      string
		doc       []byte
		approvals []verify.Approval
		check     int   // the failing check, 0 when accepted
		want      error // for check 2
	}{
		{name: "good update", doc: next, approvals: approvals(next, alex, sam)},
		{name: "good update, extra and bad approvals ignored", doc: next, approvals: append(approvals(next, eve, alex, kim), policySig)},
		{name: "wrong kind", doc: withKeys(map[string]any{"kind": "bifrost.envelope"}), check: 1},
		{name: "unknown field", doc: withKeys(map[string]any{"note": "hi"}), check: 1},
		{name: "duplicate json key", doc: []byte(strings.Replace(string(next), `"v":1`, `"v":1,"v":1`, 1)), check: 1},
		{name: "duplicate key_id", doc: withKeys(map[string]any{"keys": []any{alex.Entry(), alex.Entry()}}), check: 1},
		{name: "same serial", doc: testkit.KeySet(4, 2, alex, sam), want: verify.ErrKeySetStale},
		{name: "older serial", doc: testkit.KeySet(2, 2, alex, sam), want: verify.ErrKeySetStale},
		{name: "serial gap", doc: testkit.KeySet(6, 2, alex, sam), want: verify.ErrKeySetGap},
		{name: "other organization", doc: withKeys(map[string]any{"organization_id": "01JOTHER"}), check: 3},
		{name: "threshold 0", doc: withKeys(map[string]any{"update_threshold": 0}), check: 4},
		{name: "threshold above owners", doc: withKeys(map[string]any{"update_threshold": 3}), check: 4},
		{name: "no passkey", doc: withKeys(map[string]any{"keys": []any{policyEntry}}), check: 4},
		{name: "signed by keys not in the current set", doc: next, approvals: approvals(next, eve, testkit.NewApprover("user:mal")), check: 5},
		{name: "signed by keys only in the new set", doc: testkit.KeySet(5, 1, eve), approvals: approvals(testkit.KeySet(5, 1, eve), eve, alex), check: 5},
		{name: "policy only", doc: next, approvals: []verify.Approval{policySig}, check: 5},
		{name: "one owner", doc: next, approvals: approvals(next, sam), check: 5},
		{name: "same owner twice counts once", doc: next, approvals: approvals(next, alex, alexSpare), check: 5},
		{name: "approvals over another document", doc: next, approvals: approvals(testkit.KeySet(5, 1, alex), alex, sam), check: 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := verify.CheckKeySetUpdate(current, c.doc, c.approvals)
			switch {
			case c.want != nil:
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v", err, c.want)
				}
			case c.check != 0:
				var r *verify.Rejection
				if !errors.As(err, &r) || r.Check != c.check {
					t.Fatalf("err = %v, want check %d", err, c.check)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if got.Serial != 5 || got.Len() != 2 || got.UpdateThreshold != 2 {
					t.Fatalf("got = %+v", got)
				}
			}
		})
	}
}

func TestCheckKeySetUpdateFromLegacy(t *testing.T) {
	alex, sam := testkit.NewApprover("user:alex"), testkit.NewApprover("user:sam")
	legacy := testkit.TrustedKeys(alex)
	first := testkit.KeySetWith(map[string]any{"organization_id": "01JANY", "keys": []any{alex.Entry(), sam.Entry()}})
	got, err := verify.CheckKeySetUpdate(legacy, first, testkit.Update(first, alex).Approvals)
	if err != nil || got.Serial != 1 || got.OrganizationID != "01JANY" {
		t.Fatalf("got = %+v, %v", got, err)
	}
	// An empty legacy set never accepts an update.
	empty, _ := verify.ParseTrustedKeys([]byte(`{"v":1,"keys":[]}`))
	if _, err := verify.CheckKeySetUpdate(empty, first, testkit.Update(first, alex).Approvals); err == nil {
		t.Fatal("empty set accepted an update")
	}
}
