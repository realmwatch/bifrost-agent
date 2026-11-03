package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/realmwatch/bifrost-agent/internal/catalog"
	"github.com/realmwatch/bifrost-agent/internal/nonce"
	"github.com/realmwatch/bifrost-agent/operations"
)

const (
	testMachineID = "0123456789abcdef0123456789abcdef"
	testRPID      = "approve.example.com"
	testOrigin    = "https://approve.example.com"
	testNonce     = "aa00000000000000000000000000000000000000000000000000000000000001"
)

var testNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// signer is an approver's passkey.
type signer struct {
	keyID string
	owner string
	alg   int
	priv  crypto.Signer
}

func (s signer) sign(msg []byte) []byte {
	switch s.alg {
	case AlgEdDSA:
		return ed25519.Sign(s.priv.(ed25519.PrivateKey), msg)
	case AlgES256:
		d := sha256.Sum256(msg)
		sig, err := ecdsa.SignASN1(rand.Reader, s.priv.(*ecdsa.PrivateKey), d[:])
		if err != nil {
			panic(err)
		}
		return sig
	case AlgRS256:
		d := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv.(*rsa.PrivateKey), crypto.SHA256, d[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
	panic("alg")
}

type fixture struct {
	es, es2, ed, rsa, untrusted signer
	policy                      ed25519.PrivateKey
	keysJSON                    []byte
}

var (
	fixOnce sync.Once
	fix     fixture
)

func getFixture(t *testing.T) fixture {
	t.Helper()
	fixOnce.Do(func() {
		ec1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ec2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ec3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, edk, _ := ed25519.GenerateKey(rand.Reader)
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		ppub, ppriv, _ := ed25519.GenerateKey(rand.Reader)
		fix = fixture{
			es:        signer{B64U([]byte("cred-es-1")), "user:alex", AlgES256, ec1},
			es2:       signer{B64U([]byte("cred-es-2")), "user:sam", AlgES256, ec2},
			ed:        signer{B64U([]byte("cred-ed")), "user:alex", AlgEdDSA, edk},
			rsa:       signer{B64U([]byte("cred-rsa")), "user:kim", AlgRS256, rk},
			untrusted: signer{B64U([]byte("cred-x")), "user:eve", AlgES256, ec3},
			policy:    ppriv,
		}
		var keys []map[string]any
		for _, s := range []signer{fix.es, fix.es2, fix.ed, fix.rsa} {
			spki, err := x509.MarshalPKIXPublicKey(s.priv.Public())
			if err != nil {
				panic(err)
			}
			keys = append(keys, map[string]any{
				"kind": "passkey", "key_id": s.keyID, "owner": s.owner, "label": "test",
				"alg": s.alg, "public_key": B64U(spki), "rp_id": testRPID, "origin": testOrigin,
			})
		}
		keys = append(keys, map[string]any{"kind": "policy", "key_id": "policy-1", "public_key": B64U(ppub)})
		fix.keysJSON, _ = json.Marshal(map[string]any{"v": 1, "keys": keys})
	})
	return fix
}

// assertion options; zero values mean "correct".
type assertOpts struct {
	typ       string
	challenge string
	origin    string
	rpID      string
	flags     byte
	cross     bool
	tamper    bool
}

func passkey(s signer, envelope []byte, o assertOpts) Approval {
	hash := sha256.Sum256(envelope)
	if o.typ == "" {
		o.typ = "webauthn.get"
	}
	if o.challenge == "" {
		o.challenge = B64U(hash[:])
	}
	if o.origin == "" {
		o.origin = testOrigin
	}
	if o.rpID == "" {
		o.rpID = testRPID
	}
	if o.flags == 0 {
		o.flags = flagUserPresent | flagUserVerified
	}
	cd := map[string]any{"type": o.typ, "challenge": o.challenge, "origin": o.origin}
	if o.cross {
		cd["crossOrigin"] = true
	}
	cdj, _ := json.Marshal(cd)
	rp := sha256.Sum256([]byte(o.rpID))
	authData := append(append(rp[:], o.flags), 0, 0, 0, 7) // sign count 7
	cdHash := sha256.Sum256(cdj)
	sig := s.sign(append(append([]byte{}, authData...), cdHash[:]...))
	if o.tamper {
		sig[len(sig)-1] ^= 0xff
	}
	return Approval{Kind: "passkey", KeyID: s.keyID, AuthenticatorData: B64U(authData), ClientDataJSON: B64U(cdj), Signature: B64U(sig)}
}

func policyApproval(f fixture, envelope []byte) Approval {
	return Approval{Kind: "policy", KeyID: "policy-1", Signature: B64U(ed25519.Sign(f.policy, envelope))}
}

func envelopeMap() map[string]any {
	return map[string]any{
		"v": 1, "kind": "bifrost.envelope", "proposal_id": "01JPROPOSAL", "organization_id": "01JORG",
		"hosts":        []any{map[string]any{"server_id": "01JSERVER", "name": "web-01", "machine_id": testMachineID}},
		"operations":   []any{map[string]any{"op": "package.upgrade", "version": 1, "params": map[string]any{"name": "openssl", "to": "3.0.13-0ubuntu3.4"}}},
		"rollback":     []any{map[string]any{"op": "package.install", "version": 1, "params": map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.1"}}},
		"irreversible": false, "intent": "Fix CVE-2026-1234 in openssl on web-01", "risk_tier": "low",
		"not_before": nil, "expires_at": "2026-11-01T00:00:00Z", "nonce": testNonce,
	}
}

func encode(m map[string]any) []byte {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func restartEnvelope() map[string]any {
	m := envelopeMap()
	m["operations"] = []any{map[string]any{"op": "service.restart", "version": 1, "params": map[string]any{"unit": "nginx.service"}}}
	m["rollback"] = []any{}
	return m
}

const criticalDef = `{
  "name": "test.critical", "version": 1, "description": "A critical test operation.", "min_tier": "critical",
  "params": {"type":"object","additionalProperties":false,"properties":{}},
  "rollback": null, "irreversible": true, "health_check": "h", "files_written": [],
  "agent": {"privileged": false, "argv": {"apt": ["/bin/true"], "dnf": ["/bin/true"]},
    "health": {"check": "service_state", "args": {"unit": "x.service", "state": "active"}}}
}`

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	m := fstest.MapFS{"test.critical@1.json": {Data: []byte(criticalDef)}}
	files, _ := fs.Glob(operations.FS, "*.json")
	for _, f := range files {
		data, _ := fs.ReadFile(operations.FS, f)
		m[f] = &fstest.MapFile{Data: data}
	}
	c, err := catalog.Load(m)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	f := getFixture(t)
	keys, err := ParseTrustedKeys(f.keysJSON)
	if err != nil {
		t.Fatal(err)
	}
	store, err := nonce.Open(filepath.Join(t.TempDir(), "nonces.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Verifier{
		Catalog: testCatalog(t), Keys: keys, MachineID: testMachineID, PackageManager: "apt",
		Nonces: store, Now: func() time.Time { return testNow }, DenyRules: CompiledDenyRules,
	}
}

func TestVerify(t *testing.T) {
	f := getFixture(t)
	type tc struct {
		name      string
		envelope  func() []byte
		approvals func(env []byte) []Approval
		setup     func(v *Verifier)
		wantCheck int // 0 means accept
		wantIn    string
	}
	std := func() []byte { return encode(envelopeMap()) }
	with := func(edit func(m map[string]any)) func() []byte {
		return func() []byte {
			m := envelopeMap()
			edit(m)
			return encode(m)
		}
	}
	one := func(o assertOpts) func([]byte) []Approval {
		return func(env []byte) []Approval { return []Approval{passkey(f.es, env, o)} }
	}
	good := one(assertOpts{})
	cases := []tc{
		{name: "es256 accepted", envelope: std, approvals: good},
		{name: "eddsa accepted", envelope: std, approvals: func(e []byte) []Approval { return []Approval{passkey(f.ed, e, assertOpts{})} }},
		{name: "rs256 accepted", envelope: std, approvals: func(e []byte) []Approval { return []Approval{passkey(f.rsa, e, assertOpts{})} }},
		{name: "invalid approval ignored beside a valid one", envelope: std, approvals: func(e []byte) []Approval {
			return []Approval{passkey(f.untrusted, e, assertOpts{}), passkey(f.es, e, assertOpts{})}
		}},
		{name: "not_before passed", envelope: with(func(m map[string]any) { m["not_before"] = "2026-10-31T11:00:00Z" }), approvals: good},

		// 1. parse
		{name: "not json", envelope: func() []byte { return []byte("{") }, approvals: good, wantCheck: 1, wantIn: "bad envelope"},
		{name: "wrong version", envelope: with(func(m map[string]any) { m["v"] = 2 }), approvals: good, wantCheck: 1, wantIn: "version"},
		{name: "wrong kind", envelope: with(func(m map[string]any) { m["kind"] = "other" }), approvals: good, wantCheck: 1, wantIn: "kind"},
		{name: "unknown field", envelope: with(func(m map[string]any) { m["extra"] = 1 }), approvals: good, wantCheck: 1, wantIn: "unknown field"},
		{name: "no operations", envelope: with(func(m map[string]any) { m["operations"] = []any{} }), approvals: good, wantCheck: 1, wantIn: "no operations"},
		{name: "params not object", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "service.restart", "version": 1, "params": []any{}}}
		}), approvals: good, wantCheck: 1, wantIn: "params must be an object"},
		{name: "bad expiry", envelope: with(func(m map[string]any) { m["expires_at"] = "tomorrow" }), approvals: good, wantCheck: 1, wantIn: "expires_at"},
		{name: "duplicate top-level key", envelope: func() []byte {
			b := std()
			return append(b[:len(b)-1], []byte(`,"nonce":"`+strings.Repeat("b", 64)+`"}`)...)
		}, approvals: good, wantCheck: 1, wantIn: "duplicate JSON key"},
		{name: "duplicate nested key", envelope: func() []byte {
			return []byte(strings.Replace(string(std()), `"name":"openssl"`, `"name":"openssl","name":"libc6"`, 1))
		}, approvals: good, wantCheck: 1, wantIn: "duplicate JSON key"},
		{name: "duplicate key in array object", envelope: func() []byte {
			return []byte(strings.Replace(string(std()), `"machine_id":"`, `"machine_id":"x","machine_id":"`, 1))
		}, approvals: good, wantCheck: 1, wantIn: "duplicate JSON key"},
		{name: "trailing data", envelope: func() []byte { return append(std(), []byte(" {}")...) }, approvals: good, wantCheck: 1, wantIn: "trailing"},

		// 2. host
		{name: "wrong host", envelope: with(func(m map[string]any) {
			m["hosts"] = []any{map[string]any{"server_id": "x", "name": "web-02", "machine_id": "ffff"}}
		}), approvals: good, wantCheck: 2, wantIn: "wrong host"},
		{name: "empty machine id", envelope: std, approvals: good, setup: func(v *Verifier) { v.MachineID = "" }, wantCheck: 2},

		// 3. time
		{name: "expired", envelope: with(func(m map[string]any) { m["expires_at"] = "2026-10-31T12:00:00Z" }), approvals: good, wantCheck: 3, wantIn: "expired"},
		{name: "not yet valid", envelope: with(func(m map[string]any) { m["not_before"] = "2026-10-31T13:00:00Z" }), approvals: good, wantCheck: 3, wantIn: "not yet valid"},

		// 4. nonce
		{name: "replayed nonce", envelope: std, approvals: good, setup: func(v *Verifier) {
			_ = v.Nonces.Add(testNonce, testNow.Add(time.Hour), testNow)
		}, wantCheck: 4, wantIn: "replayed nonce"},
		{name: "malformed nonce", envelope: with(func(m map[string]any) { m["nonce"] = "abc" }), approvals: good, wantCheck: 4, wantIn: "bad nonce"},

		// 5. operations
		{name: "unknown op", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "shell.exec", "version": 1, "params": map[string]any{}}}
		}), approvals: good, wantCheck: 5, wantIn: "unknown operation shell.exec@1"},
		{name: "unknown version", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "service.restart", "version": 2, "params": map[string]any{"unit": "nginx.service"}}}
		}), approvals: good, wantCheck: 5, wantIn: "unknown operation"},
		{name: "unknown rollback op", envelope: with(func(m map[string]any) {
			m["rollback"] = []any{map[string]any{"op": "package.remove", "version": 1, "params": map[string]any{}}}
		}), approvals: good, wantCheck: 5, wantIn: "unknown operation package.remove@1"},
		{name: "bad params", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "package.upgrade", "version": 1, "params": map[string]any{"name": "openssl; reboot", "to": "1"}}}
		}), approvals: good, wantCheck: 5, wantIn: "bad params"},
		{name: "extra param", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "service.restart", "version": 1, "params": map[string]any{"unit": "nginx.service", "now": true}}}
		}), approvals: good, wantCheck: 5, wantIn: "unexpected property"},
		{name: "bad rollback params", envelope: with(func(m map[string]any) {
			m["rollback"] = []any{map[string]any{"op": "package.install", "version": 1, "params": map[string]any{"name": "openssl"}}}
		}), approvals: good, wantCheck: 5, wantIn: "rollback[0]"},
		{name: "package op without package manager", envelope: std, approvals: good, setup: func(v *Verifier) { v.PackageManager = "" }, wantCheck: 5, wantIn: "not supported"},

		// 6. deny rules
		{name: "deny rule", envelope: std, approvals: good, setup: func(v *Verifier) {
			v.DenyRules = []DenyRule{{Name: "no-openssl", Match: func(d *catalog.Definition, p map[string]any) (string, bool) {
				return "openssl is pinned", d.Name == "package.upgrade" && p["name"] == "openssl"
			}}}
		}, wantCheck: 6, wantIn: "denied by agent rule no-openssl"},
		{name: "deny rule not matching", envelope: std, approvals: good, setup: func(v *Verifier) {
			v.DenyRules = []DenyRule{{Name: "no-curl", Match: func(d *catalog.Definition, p map[string]any) (string, bool) {
				return "", p["name"] == "curl"
			}}}
		}},

		// 7. approvals: passkey checks
		{name: "no approvals", envelope: std, approvals: func([]byte) []Approval { return nil }, wantCheck: 7, wantIn: "no valid passkey"},
		{name: "wrong origin", envelope: std, approvals: one(assertOpts{origin: "https://evil.example.com"}), wantCheck: 7},
		{name: "wrong challenge", envelope: std, approvals: one(assertOpts{challenge: B64U([]byte("other"))}), wantCheck: 7},
		{name: "wrong type", envelope: std, approvals: one(assertOpts{typ: "webauthn.create"}), wantCheck: 7},
		{name: "missing UV", envelope: std, approvals: one(assertOpts{flags: flagUserPresent}), wantCheck: 7},
		{name: "missing UP", envelope: std, approvals: one(assertOpts{flags: flagUserVerified}), wantCheck: 7},
		{name: "wrong rp hash", envelope: std, approvals: one(assertOpts{rpID: "evil.example.com"}), wantCheck: 7},
		{name: "cross origin", envelope: std, approvals: one(assertOpts{cross: true}), wantCheck: 7},
		{name: "bad signature", envelope: std, approvals: one(assertOpts{tamper: true}), wantCheck: 7},
		{name: "signature over other envelope", envelope: std, approvals: func([]byte) []Approval {
			return []Approval{passkey(f.es, encode(restartEnvelope()), assertOpts{})}
		}, wantCheck: 7},
		{name: "untrusted key", envelope: std, approvals: func(e []byte) []Approval { return []Approval{passkey(f.untrusted, e, assertOpts{})} }, wantCheck: 7},
		{name: "key id of another key", envelope: std, approvals: func(e []byte) []Approval {
			a := passkey(f.untrusted, e, assertOpts{})
			a.KeyID = f.es.keyID
			return []Approval{a}
		}, wantCheck: 7},
		{name: "unknown approval kind", envelope: std, approvals: func(e []byte) []Approval {
			return []Approval{{Kind: "password", KeyID: "x", Signature: "x"}}
		}, wantCheck: 7},

		// 7. tiers
		{name: "critical with one owner", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "test.critical", "version": 1, "params": map[string]any{}}}
			m["rollback"] = []any{}
		}), approvals: func(e []byte) []Approval {
			return []Approval{passkey(f.es, e, assertOpts{}), passkey(f.ed, e, assertOpts{})}
		},
			wantCheck: 7, wantIn: "two different owners"},
		{name: "critical with two owners", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "test.critical", "version": 1, "params": map[string]any{}}}
			m["rollback"] = []any{}
		}), approvals: func(e []byte) []Approval {
			return []Approval{passkey(f.es, e, assertOpts{}), passkey(f.es2, e, assertOpts{})}
		}},
		{name: "envelope risk_tier ignored", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "test.critical", "version": 1, "params": map[string]any{}}}
			m["rollback"] = []any{}
			m["risk_tier"] = "low"
		}), approvals: good, wantCheck: 7, wantIn: "two different owners"},

		// 7. policy approvals
		{name: "policy only for auto-approved op", envelope: func() []byte { return encode(restartEnvelope()) },
			approvals: func(e []byte) []Approval { return []Approval{policyApproval(f, e)} }},
		{name: "policy only for non-listed op", envelope: std,
			approvals: func(e []byte) []Approval { return []Approval{policyApproval(f, e)} }, wantCheck: 7, wantIn: "policy approval alone cannot approve package.upgrade@1"},
		{name: "policy with bad signature", envelope: func() []byte { return encode(restartEnvelope()) },
			approvals: func(e []byte) []Approval { return []Approval{policyApproval(f, append([]byte(" "), e...))} }, wantCheck: 7},
		{name: "policy unknown key", envelope: func() []byte { return encode(restartEnvelope()) },
			approvals: func(e []byte) []Approval { a := policyApproval(f, e); a.KeyID = "policy-2"; return []Approval{a} }, wantCheck: 7},
		{name: "policy plus passkey for non-listed op", envelope: std,
			approvals: func(e []byte) []Approval { return []Approval{policyApproval(f, e), passkey(f.es, e, assertOpts{})} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newVerifier(t)
			if c.setup != nil {
				c.setup(v)
			}
			env := c.envelope()
			res, err := v.Verify(env, c.approvals(env))
			if c.wantCheck == 0 {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				if res.Envelope.Hash != sha256.Sum256(env) {
					t.Fatal("hash mismatch")
				}
				return
			}
			var r *Rejection
			if !errors.As(err, &r) {
				t.Fatalf("err = %v, want a rejection at check %d", err, c.wantCheck)
			}
			if r.Check != c.wantCheck || !strings.Contains(r.Reason, c.wantIn) {
				t.Fatalf("rejection = %v, want check %d containing %q", r, c.wantCheck, c.wantIn)
			}
			if want, ok := wantDetail[c.name]; ok && !strings.Contains(r.Detail, want) {
				t.Fatalf("detail = %q, want containing %q", r.Detail, want)
			}
		})
	}
}

// wantDetail pins why each rejected approval failed.
var wantDetail = map[string]string{
	"wrong origin":                  "origin",
	"wrong challenge":               "challenge does not match",
	"wrong type":                    "want webauthn.get",
	"missing UV":                    "user verification flag",
	"missing UP":                    "user presence flag",
	"wrong rp hash":                 "rp_id hash",
	"cross origin":                  "cross-origin",
	"bad signature":                 "signature does not verify",
	"signature over other envelope": "challenge does not match",
	"untrusted key":                 "untrusted passkey",
	"key id of another key":         "signature does not verify",
	"unknown approval kind":         "unknown kind",
	"policy with bad signature":     "signature does not verify",
	"policy unknown key":            "untrusted policy key",
	"duplicate top-level key":       `"nonce"`,
}

func TestDuplicateKeyReasonIsExact(t *testing.T) {
	v := newVerifier(t)
	_, err := v.Verify([]byte(`{"v":1,"v":1}`), nil)
	var r *Rejection
	if !errors.As(err, &r) || r.Reason != "duplicate JSON key" || r.Check != CheckParse {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyAndConsumeBlocksReplay(t *testing.T) {
	f := getFixture(t)
	v := newVerifier(t)
	env := encode(envelopeMap())
	approvals := []Approval{passkey(f.es, env, assertOpts{})}
	res, err := v.VerifyAndConsume(env, approvals)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != catalog.TierMedium || len(res.Owners) != 1 || res.Owners[0] != "user:alex" || res.PolicyOnly {
		t.Fatalf("result = %+v", res)
	}
	_, err = v.VerifyAndConsume(env, approvals)
	var r *Rejection
	if !errors.As(err, &r) || r.Check != CheckNonce {
		t.Fatalf("replay err = %v", err)
	}
}

func TestPolicyOnlyResult(t *testing.T) {
	f := getFixture(t)
	v := newVerifier(t)
	env := encode(restartEnvelope())
	res, err := v.Verify(env, []Approval{policyApproval(f, env)})
	if err != nil || !res.PolicyOnly || res.Tier != catalog.TierLow {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	// A custom auto-approval list without the op refuses it.
	v.AutoApprove = []string{}
	if _, err := v.Verify(env, []Approval{policyApproval(f, env)}); err == nil {
		t.Fatal("empty auto-approval list accepted policy-only")
	}
}

func TestParseTrustedKeysRejects(t *testing.T) {
	f := getFixture(t)
	if _, err := ParseTrustedKeys(f.keysJSON); err != nil {
		t.Fatal(err)
	}
	ecSPKI, _ := x509.MarshalPKIXPublicKey(f.es.priv.Public())
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384SPKI, _ := x509.MarshalPKIXPublicKey(p384.Public())
	pk := func(edit func(m map[string]any)) string {
		m := map[string]any{"kind": "passkey", "key_id": "Y3JlZA", "owner": "user:a", "alg": -7,
			"public_key": B64U(ecSPKI), "rp_id": testRPID, "origin": testOrigin}
		edit(m)
		b, _ := json.Marshal(map[string]any{"v": 1, "keys": []any{m}})
		return string(b)
	}
	cases := map[string]string{
		"valid control":      "",
		"bad version":        `{"v":2,"keys":[]}`,
		"unknown kind":       `{"v":1,"keys":[{"kind":"ssh","key_id":"a","public_key":"AA"}]}`,
		"short policy key":   `{"v":1,"keys":[{"kind":"policy","key_id":"p","public_key":"AAAA"}]}`,
		"unknown field":      pk(func(m map[string]any) { m["extra"] = 1 }),
		"no owner":           pk(func(m map[string]any) { delete(m, "owner") }),
		"alg mismatch":       pk(func(m map[string]any) { m["alg"] = -8 }),
		"unsupported alg":    pk(func(m map[string]any) { m["alg"] = -35 }),
		"wrong curve":        pk(func(m map[string]any) { m["public_key"] = B64U(p384SPKI) }),
		"http origin":        pk(func(m map[string]any) { m["origin"] = "http://approve.example.com" }),
		"origin with path":   pk(func(m map[string]any) { m["origin"] = "https://approve.example.com/app" }),
		"garbage public key": pk(func(m map[string]any) { m["public_key"] = "AAAA" }),
		"duplicate json key": `{"v":1,"v":1,"keys":[]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "valid control" {
				if _, err := ParseTrustedKeys([]byte(pk(func(map[string]any) {}))); err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, err := ParseTrustedKeys([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	one := strings.TrimSuffix(strings.TrimPrefix(pk(func(map[string]any) {}), `{"keys":[`), `],"v":1}`)
	if _, err := ParseTrustedKeys([]byte(`{"v":1,"keys":[` + one + "," + one + `]}`)); err == nil {
		t.Fatal("duplicate key_id accepted")
	}
}
