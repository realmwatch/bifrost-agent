package nonce

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsAndPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("a", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("a", now.Add(time.Hour), now); err == nil {
		t.Fatal("duplicate nonce accepted")
	}
	if err := s.Add("b", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode = %v, %v", info.Mode(), err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Seen("a") || !s2.Seen("b") || s2.Seen("c") {
		t.Fatal("reloaded store lost nonces")
	}
	// Adding after a's expiry prunes it.
	if err := s2.Add("c", now.Add(2*time.Hour), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s2.Seen("a") || s2.Len() != 2 {
		t.Fatalf("expired nonce not pruned: len %d", s2.Len())
	}
}

func TestCorruptStoreFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt store opened")
	}
}

func TestMemoryStore(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.Add("x", now.Add(time.Minute), now); err != nil || !s.Seen("x") {
		t.Fatal("memory store failed")
	}
}
