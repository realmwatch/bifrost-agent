package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func batchMap(org string, hashes ...string) map[string]any {
	envs := []any{}
	for _, h := range hashes {
		envs = append(envs, h)
	}
	return map[string]any{"v": 1, "kind": "bifrost.batch", "organization_id": org, "envelopes": envs}
}

// batchApproval signs a WebAuthn assertion over the batch hash and carries
// the batch bytes, as the hub hands it to every agent in the batch.
func batchApproval(s signer, batch []byte) Approval {
	a := passkey(s, batch, assertOpts{})
	a.Kind = "passkey_batch"
	a.Batch = B64U(batch)
	return a
}

func TestBatchApproval(t *testing.T) {
	f := getFixture(t)
	other := hashHex([]byte("another envelope"))
	std := func() []byte { return encode(envelopeMap()) }
	with := func(edit func(m map[string]any)) func() []byte {
		return func() []byte {
			m := envelopeMap()
			edit(m)
			return encode(m)
		}
	}
	// batch builds the batch bytes for an envelope.
	type batchFn func(env []byte) []byte
	listing := func(edit func(env []byte, m map[string]any)) batchFn {
		return func(env []byte) []byte {
			m := batchMap("01JORG", other, hashHex(env))
			if edit != nil {
				edit(env, m)
			}
			return encode(m)
		}
	}
	good := listing(nil)
	hashes := func(n int, env []byte) []any {
		out := []any{hashHex(env)}
		for i := 1; i < n; i++ {
			out = append(out, fmt.Sprintf("%064x", i))
		}
		return out
	}
	critical := with(func(m map[string]any) {
		m["operations"] = []any{map[string]any{"op": "test.critical", "version": 1, "params": map[string]any{}}}
		m["rollback"] = []any{}
	})
	batchCritical := func(v *Verifier) {
		v.BatchApprove = &BatchList{Operations: []string{"test.critical@1"}}
	}

	cases := []struct {
		name      string
		envelope  func() []byte
		batch     batchFn
		approvals func(env, batch []byte) []Approval // nil means one batch approval from f.es
		setup     func(v *Verifier)
		wantErr   string // empty means accepted; otherwise in the ignored detail
		wantIn    string // in the rejection reason; default "no valid passkey"
	}{
		{name: "valid batch", envelope: std, batch: good},
		{name: "batch of one", envelope: std, batch: func(env []byte) []byte { return encode(batchMap("01JORG", hashHex(env))) }},
		{name: "batch of 100", envelope: std, batch: listing(func(env []byte, m map[string]any) { m["envelopes"] = hashes(100, env) })},
		{name: "packages.upgrade batchable", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "packages.upgrade", "version": 1, "params": map[string]any{
				"packages": []any{map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.4"}}}}}
		}), batch: good},
		{name: "no rollback batchable", envelope: with(func(m map[string]any) { m["rollback"] = []any{} }), batch: good},
		{name: "eddsa batch", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			return []Approval{batchApproval(f.ed, batch)}
		}},

		{name: "envelope not in batch", envelope: std, batch: func([]byte) []byte { return encode(batchMap("01JORG", other)) },
			wantErr: "envelope is not in the batch"},
		{name: "other organization", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["organization_id"] = "01JOTHER" }),
			wantErr: "organization_id"},
		{name: "no organization", envelope: std, batch: listing(func(_ []byte, m map[string]any) { delete(m, "organization_id") }),
			wantErr: "no organization_id"},
		{name: "duplicate key", envelope: std, batch: func(env []byte) []byte {
			b := good(env)
			return append(b[:len(b)-1], []byte(`,"organization_id":"01JORG"}`)...)
		}, wantErr: "duplicate JSON key"},
		{name: "trailing data", envelope: std, batch: func(env []byte) []byte { return append(good(env), []byte(" {}")...) },
			wantErr: "trailing"},
		{name: "unknown field", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["hosts"] = []any{} }),
			wantErr: "unknown field"},
		{name: "bad kind", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["kind"] = "bifrost.envelope" }),
			wantErr: "want bifrost.batch"},
		{name: "bad version", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["v"] = 2 }),
			wantErr: "unsupported batch version 2"},
		{name: "no entries", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["envelopes"] = []any{} }),
			wantErr: "0 envelopes"},
		{name: "null entries", envelope: std, batch: listing(func(_ []byte, m map[string]any) { m["envelopes"] = nil }),
			wantErr: "0 envelopes"},
		{name: "101 entries", envelope: std, batch: listing(func(env []byte, m map[string]any) { m["envelopes"] = hashes(101, env) }),
			wantErr: "101 envelopes"},
		{name: "duplicate entries", envelope: std, batch: listing(func(env []byte, m map[string]any) {
			m["envelopes"] = []any{hashHex(env), other, hashHex(env)}
		}), wantErr: "listed twice"},
		{name: "uppercase hex", envelope: std, batch: listing(func(env []byte, m map[string]any) {
			m["envelopes"] = []any{strings.ToUpper(hashHex(env))}
		}), wantErr: "64 lowercase hex"},
		{name: "short entry", envelope: std, batch: listing(func(env []byte, m map[string]any) {
			m["envelopes"] = []any{hashHex(env)[:63]}
		}), wantErr: "64 lowercase hex"},
		{name: "not base64url", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			a := batchApproval(f.es, batch)
			a.Batch = "!!"
			return []Approval{a}
		}, wantErr: "batch:"},

		{name: "signature over the envelope hash", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			a := passkey(f.es, env, assertOpts{})
			a.Kind = "passkey_batch"
			a.Batch = B64U(batch)
			return []Approval{a}
		}, wantErr: "challenge does not match"},
		{name: "signature over another batch", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			a := batchApproval(f.es, encode(batchMap("01JORG", hashHex(env))))
			a.Batch = B64U(batch)
			return []Approval{a}
		}, wantErr: "challenge does not match"},
		{name: "untrusted key", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			return []Approval{batchApproval(f.untrusted, batch)}
		}, wantErr: "untrusted passkey"},
		{name: "plain passkey kind with a batch", envelope: std, batch: good, approvals: func(env, batch []byte) []Approval {
			a := batchApproval(f.es, batch)
			a.Kind = "passkey"
			return []Approval{a}
		}, wantErr: "challenge does not match"},

		{name: "service.restart not batchable", envelope: func() []byte { return encode(restartEnvelope()) }, batch: good,
			wantErr: "operation service.restart@1 can't be approved in a batch"},
		{name: "package.install as an operation", envelope: with(func(m map[string]any) {
			m["operations"] = []any{map[string]any{"op": "package.install", "version": 1, "params": map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.1"}}}
		}), batch: good, wantErr: "operation package.install@1 can't be approved in a batch"},
		{name: "batchable op beside one that isn't", envelope: with(func(m map[string]any) {
			m["operations"] = append(m["operations"].([]any), map[string]any{"op": "system.reboot", "version": 1, "params": map[string]any{}})
		}), batch: good, wantErr: "operation system.reboot@1 can't be approved in a batch"},
		{name: "rollback step not batchable", envelope: with(func(m map[string]any) {
			m["rollback"] = []any{map[string]any{"op": "service.restart", "version": 1, "params": map[string]any{"unit": "nginx.service"}}}
		}), batch: good, wantErr: "rollback step service.restart@1 can't be approved in a batch"},
		{name: "upgrade as a rollback step", envelope: with(func(m map[string]any) {
			m["rollback"] = []any{map[string]any{"op": "package.upgrade", "version": 1, "params": map[string]any{"name": "openssl", "to": "3.0.13-0ubuntu3.1"}}}
		}), batch: good, wantErr: "rollback step package.upgrade@1 can't be approved in a batch"},
		{name: "not batchable but a plain passkey approves", envelope: func() []byte { return encode(restartEnvelope()) }, batch: good,
			approvals: func(env, batch []byte) []Approval {
				return []Approval{batchApproval(f.es, batch), passkey(f.es, env, assertOpts{})}
			}},

		{name: "critical with one batch owner", envelope: critical, batch: good, setup: batchCritical,
			wantIn: "two different owners"},
		{name: "critical with a batch and a passkey of the same owner", envelope: critical, batch: good, setup: batchCritical,
			approvals: func(env, batch []byte) []Approval {
				return []Approval{batchApproval(f.es, batch), passkey(f.ed, env, assertOpts{})}
			}, wantIn: "two different owners"},
		{name: "critical with two batch owners", envelope: critical, batch: good, setup: batchCritical,
			approvals: func(env, batch []byte) []Approval {
				return []Approval{batchApproval(f.es, batch), batchApproval(f.es2, batch)}
			}},
		{name: "critical with a batch and another owner's passkey", envelope: critical, batch: good, setup: batchCritical,
			approvals: func(env, batch []byte) []Approval {
				return []Approval{batchApproval(f.es, batch), passkey(f.rsa, env, assertOpts{})}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newVerifier(t)
			if c.setup != nil {
				c.setup(v)
			}
			env := c.envelope()
			batch := c.batch(env)
			approvals := []Approval{batchApproval(f.es, batch)}
			if c.approvals != nil {
				approvals = c.approvals(env, batch)
			}
			res, err := v.Verify(env, approvals)
			if c.wantErr == "" && c.wantIn == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				if len(res.Owners) == 0 || res.PolicyOnly {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			var r *Rejection
			if !errors.As(err, &r) || r.Check != CheckApproval {
				t.Fatalf("err = %v, want a rejection at check %d", err, CheckApproval)
			}
			wantIn := c.wantIn
			if wantIn == "" {
				wantIn = "no valid passkey approval"
			}
			if !strings.Contains(r.Reason, wantIn) || !strings.Contains(r.Detail, c.wantErr) {
				t.Fatalf("rejection = %v, want reason containing %q and detail containing %q", r, wantIn, c.wantErr)
			}
		})
	}
}

func TestCompiledBatchApprovalIsUpdatesOnly(t *testing.T) {
	want := BatchList{Operations: []string{"package.upgrade@1", "packages.upgrade@1"}, Rollback: []string{"package.install@1"}}
	if fmt.Sprint(CompiledBatchApproval) != fmt.Sprint(want) {
		t.Fatalf("CompiledBatchApproval = %v, want %v", CompiledBatchApproval, want)
	}
	c := testCatalog(t)
	for _, k := range append(append([]string{}, want.Operations...), want.Rollback...) {
		if !contains(c.Keys(), k) {
			t.Errorf("%s is not in the catalog", k)
		}
	}
}

func TestBatchApprovalResultOwner(t *testing.T) {
	f := getFixture(t)
	v := newVerifier(t)
	env := encode(envelopeMap())
	batch := encode(batchMap("01JORG", hashHex(env)))
	res, err := v.Verify(env, []Approval{batchApproval(f.es2, batch)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Owners) != 1 || res.Owners[0] != "user:sam" || len(res.Ignored) != 0 {
		t.Fatalf("result = %+v", res)
	}
}
