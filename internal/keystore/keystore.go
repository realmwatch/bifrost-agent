// Package keystore holds the key set the agent trusts: the anchor file an
// admin installed, plus the signed updates the agent accepted since
// (PROTOCOL.md, Trusted keys).
package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/realmwatch/bifrost-agent/internal/config"
	"github.com/realmwatch/bifrost-agent/internal/verify"
)

// Store reads the anchor and the stored updates. It keeps nothing in
// memory: every Load starts again from the files, so a newer anchor
// installed by hand takes effect without a restart.
type Store struct {
	// AnchorPath is the trusted keys file.
	AnchorPath string
	// Dir holds accepted updates as <serial>.json (state_dir/keysets).
	Dir string
	Log *slog.Logger
}

// New returns the store for a config.
func New(cfg config.Config, log *slog.Logger) *Store {
	return &Store{AnchorPath: cfg.TrustedKeysPath, Dir: filepath.Join(cfg.StateDir, "keysets"), Log: log}
}

// Status describes a load.
type Status struct {
	// Keys is the key set trusted now.
	Keys *verify.TrustedKeys
	// AnchorSerial is the anchor's serial (0 for a legacy file).
	AnchorSerial int
	// Applied counts the stored updates applied over the anchor.
	Applied int
}

// Load returns the key set trusted now.
func (s *Store) Load() (*verify.TrustedKeys, error) {
	st, err := s.Status()
	return st.Keys, err
}

// Status loads the anchor and re-checks each stored update above its
// serial, in serial order, against the set before it. The chain stops at
// the first missing or failing update, which is logged.
func (s *Store) Status() (Status, error) {
	anchor, err := verify.LoadTrustedKeys(s.AnchorPath)
	if err != nil {
		return Status{}, err
	}
	st := Status{Keys: anchor, AnchorSerial: anchor.Serial}
	serials, err := s.storedSerials()
	if err != nil {
		s.log().Warn("cannot list stored key set updates; using the anchor alone", "dir", s.Dir, "err", err)
		return st, nil
	}
	for _, serial := range serials {
		if serial <= st.Keys.Serial {
			continue
		}
		if serial != st.Keys.Serial+1 {
			s.log().Warn("stored key set updates skip a serial; ignoring the rest", "serial", serial, "current", st.Keys.Serial)
			break
		}
		next, err := s.loadStored(st.Keys, serial)
		if err != nil {
			s.log().Error("stored key set update does not verify; ignoring it and any after it", "serial", serial, "err", err)
			break
		}
		st.Keys = next
		st.Applied++
	}
	return st, nil
}

// storedSerials lists the serials of <serial>.json files in Dir, sorted.
func (s *Store) storedSerials() ([]int, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var serials []int
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(name)
		if err != nil || n < 1 || strconv.Itoa(n) != name {
			continue
		}
		serials = append(serials, n)
	}
	sort.Ints(serials)
	return serials, nil
}

func (s *Store) loadStored(current *verify.TrustedKeys, serial int) (*verify.TrustedKeys, error) {
	data, err := os.ReadFile(s.path(serial))
	if err != nil {
		return nil, err
	}
	var u verify.KeySetUpdate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&u); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path(serial), err)
	}
	// The chain only reaches this file when serial is current's plus one,
	// so check 2 also proves the file holds the serial its name says.
	return check(current, u)
}

// Apply checks an update against the key set trusted now and, if it
// passes, stores it. It returns the new set, or nil with a nil error for
// an update at or below the current serial (ignored). A gap returns an
// error wrapping verify.ErrKeySetGap; other failures a *verify.Rejection.
func (s *Store) Apply(u verify.KeySetUpdate) (*verify.TrustedKeys, error) {
	current, err := s.Load()
	if err != nil {
		return nil, err
	}
	next, err := check(current, u)
	if errors.Is(err, verify.ErrKeySetStale) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	// WriteFileAtomic creates Dir with mode 0700.
	if err := config.WriteFileAtomic(s.path(next.Serial), append(data, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("storing key set %d: %w", next.Serial, err)
	}
	return next, nil
}

func check(current *verify.TrustedKeys, u verify.KeySetUpdate) (*verify.TrustedKeys, error) {
	raw, err := verify.DecodeB64U(u.KeySet)
	if err != nil {
		return nil, &verify.Rejection{Check: verify.KeySetCheckParse, Reason: "bad key set: not base64url"}
	}
	return verify.CheckKeySetUpdate(current, raw, u.Approvals)
}

func (s *Store) path(serial int) string {
	return filepath.Join(s.Dir, strconv.Itoa(serial)+".json")
}

func (s *Store) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
