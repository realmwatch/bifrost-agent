package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/realmwatch/bifrost-agent/internal/testkit"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

type chain struct {
	alex, sam *testkit.Approver
	// updates[i] is serial i+2, each signed by alex over the one before.
	updates []verify.KeySetUpdate
}

func newChain(n int) chain {
	c := chain{alex: testkit.NewApprover("user:alex"), sam: testkit.NewApprover("user:sam")}
	for serial := 2; serial < 2+n; serial++ {
		c.updates = append(c.updates, testkit.Update(testkit.KeySet(serial, 1, c.alex, c.sam), c.alex))
	}
	return c
}

func newStore(t *testing.T, anchor []byte) (*Store, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trusted-keys.json")
	if err := os.WriteFile(path, anchor, 0o644); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return &Store{AnchorPath: path, Dir: filepath.Join(dir, "keysets"), Log: slog.New(slog.NewTextHandler(&logs, nil))}, &logs
}

func mustSerial(t *testing.T, s *Store, want, applied int) {
	t.Helper()
	st, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Keys.Serial != want || st.Applied != applied {
		t.Fatalf("serial %d applied %d, want %d and %d", st.Keys.Serial, st.Applied, want, applied)
	}
}

func TestApplyAndLoad(t *testing.T) {
	c := newChain(3)
	s, _ := newStore(t, testkit.KeySet(1, 1, c.alex))
	mustSerial(t, s, 1, 0)

	// A gap waits and stores nothing.
	if _, err := s.Apply(c.updates[1]); !errors.Is(err, verify.ErrKeySetGap) {
		t.Fatalf("gap = %v", err)
	}
	mustSerial(t, s, 1, 0)

	for i, u := range c.updates {
		next, err := s.Apply(u)
		if err != nil || next.Serial != i+2 {
			t.Fatalf("apply %d = %+v, %v", i+2, next, err)
		}
	}
	mustSerial(t, s, 4, 3)

	// An old serial is ignored without an error.
	if next, err := s.Apply(c.updates[0]); next != nil || err != nil {
		t.Fatalf("stale = %+v, %v", next, err)
	}

	info, err := os.Stat(s.path(3))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stored file mode = %v, %v", info, err)
	}
	if dir, err := os.Stat(s.Dir); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, %v", dir, err)
	}
	var stored verify.KeySetUpdate
	data, _ := os.ReadFile(s.path(3))
	if err := json.Unmarshal(data, &stored); err != nil || stored.KeySet != c.updates[1].KeySet || len(stored.Approvals) != 1 {
		t.Fatalf("stored = %s, %v", data, err)
	}

	// A rejected update is not stored.
	bad := testkit.Update(testkit.KeySet(5, 1, c.sam), testkit.NewApprover("user:eve"))
	var r *verify.Rejection
	if _, err := s.Apply(bad); !errors.As(err, &r) || r.Check != verify.KeySetCheckApproval {
		t.Fatalf("bad = %v", err)
	}
	if _, err := os.Stat(s.path(5)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected update was stored")
	}
}

func TestLoadChain(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(t *testing.T, s *Store, c chain)
		serial  int
		applied int
		log     string
	}{
		{name: "full chain", serial: 5, applied: 4},
		{name: "tampered file stops the chain there", serial: 3, applied: 2, log: "does not verify",
			edit: func(t *testing.T, s *Store, c chain) {
				// Serial 4 re-signed by nobody: swap in sam's set, keep alex's approval.
				u := c.updates[2]
				u.KeySet = verify.B64U(testkit.KeySet(4, 1, c.sam))
				write(t, s.path(4), u)
			}},
		{name: "file under the wrong name stops the chain", serial: 2, applied: 1, log: "does not verify",
			edit: func(t *testing.T, s *Store, c chain) { write(t, s.path(3), c.updates[0]) }},
		{name: "missing file stops the chain", serial: 3, applied: 2, log: "skip a serial",
			edit: func(t *testing.T, s *Store, c chain) { _ = os.Remove(s.path(4)) }},
		{name: "unknown field stops the chain", serial: 4, applied: 3, log: "unknown field",
			edit: func(t *testing.T, s *Store, c chain) {
				data, _ := os.ReadFile(s.path(5))
				_ = os.WriteFile(s.path(5), []byte(strings.Replace(string(data), "{", `{"x":1,`, 1)), 0o600)
			}},
		{name: "newer anchor wins", serial: 4, applied: 0, log: "does not verify",
			edit: func(t *testing.T, s *Store, c chain) {
				// The admin installs a serial 4 holding only sam: stored 2 to 4
				// are ignored, and stored 5 (signed by alex) is checked against
				// the new anchor and fails.
				_ = os.WriteFile(s.AnchorPath, testkit.KeySet(4, 1, c.sam), 0o644)
			}},
		{name: "newer anchor keeps a stored update that chains from it", serial: 5, applied: 1,
			edit: func(t *testing.T, s *Store, c chain) {
				_ = os.WriteFile(s.AnchorPath, testkit.KeySet(4, 1, c.alex), 0o644)
			}},
		{name: "newer anchor above every stored update", serial: 9, applied: 0,
			edit: func(t *testing.T, s *Store, c chain) {
				_ = os.WriteFile(s.AnchorPath, testkit.KeySet(9, 1, c.sam), 0o644)
			}},
		{name: "stray files are ignored", serial: 5, applied: 4,
			edit: func(t *testing.T, s *Store, c chain) {
				for _, name := range []string{"notes.json", "05.json", "0.json", ".tmp-1"} {
					_ = os.WriteFile(filepath.Join(s.Dir, name), []byte("junk"), 0o600)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newChain(4)
			s, logs := newStore(t, testkit.KeySet(1, 1, c.alex))
			for _, u := range c.updates {
				if _, err := s.Apply(u); err != nil {
					t.Fatal(err)
				}
			}
			if tc.edit != nil {
				tc.edit(t, s, c)
			}
			logs.Reset()
			mustSerial(t, s, tc.serial, tc.applied)
			if tc.log != "" && !strings.Contains(logs.String(), tc.log) {
				t.Fatalf("logs = %q, want %q", logs.String(), tc.log)
			}
		})
	}
}

func TestLoadBadAnchor(t *testing.T) {
	s, _ := newStore(t, []byte(`{"v":1,"keys":[],"x":1}`))
	if _, err := s.Load(); err == nil {
		t.Fatal("bad anchor loaded")
	}
	if _, err := s.Apply(newChain(1).updates[0]); err == nil {
		t.Fatal("applied over a bad anchor")
	}
}

func TestLegacyAnchorAcceptsSerialOne(t *testing.T) {
	alex := testkit.NewApprover("user:alex")
	s, _ := newStore(t, testkit.TrustedKeysJSON(alex))
	mustSerial(t, s, 0, 0)
	if _, err := s.Apply(testkit.Update(testkit.KeySet(1, 1, alex), alex)); err != nil {
		t.Fatal(err)
	}
	mustSerial(t, s, 1, 1)
}

func write(t *testing.T, path string, u verify.KeySetUpdate) {
	t.Helper()
	data, _ := json.Marshal(u)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
