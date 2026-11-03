// Package nonce remembers envelope nonces until their envelopes expire, so
// an approved envelope can run at most once.
package nonce

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrSeen reports a nonce that is already recorded.
var ErrSeen = errors.New("nonce already seen")

// Store is a persisted set of seen nonces.
type Store struct {
	mu   sync.Mutex
	path string
	// seen maps nonce to the expiry of its envelope.
	seen map[string]time.Time
}

type fileFormat struct {
	V      int                  `json:"v"`
	Nonces map[string]time.Time `json:"nonces"`
}

// Open loads the store at path, creating an empty one if it does not exist.
// An empty path gives an in-memory store.
func Open(path string) (*Store, error) {
	s := &Store{path: path, seen: map[string]time.Time{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		// A corrupt store must not silently forget nonces: fail closed.
		return nil, fmt.Errorf("nonce store %s: %w", path, err)
	}
	if f.Nonces != nil {
		s.seen = f.Nonces
	}
	return s, nil
}

// Seen reports whether nonce has been recorded and has not been pruned.
func (s *Store) Seen(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[nonce]
	return ok
}

// Add records nonce until expires, pruning expired entries, and persists
// the store. It fails if the nonce is already present.
func (s *Store) Add(nonce string, expires, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[nonce]; ok {
		return ErrSeen
	}
	for n, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, n)
		}
	}
	s.seen[nonce] = expires.UTC()
	if err := s.save(); err != nil {
		delete(s.seen, nonce)
		return err
	}
	return nil
}

// Len returns the number of remembered nonces.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	data, err := json.Marshal(fileFormat{V: 1, Nonces: s.seen})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".nonces-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
