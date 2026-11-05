package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"time"
)

// COSE algorithm identifiers the agent accepts.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// TrustedKey is one entry of the trusted keys file.
type TrustedKey struct {
	Kind      string `json:"kind"`
	KeyID     string `json:"key_id"`
	Owner     string `json:"owner,omitempty"`
	Label     string `json:"label,omitempty"`
	Alg       int    `json:"alg,omitempty"`
	PublicKey string `json:"public_key"`
	RPID      string `json:"rp_id,omitempty"`
	Origin    string `json:"origin,omitempty"`

	pub crypto.PublicKey
}

// TrustedKeys is a parsed key set: the anchor file, or the anchor with
// accepted updates applied (PROTOCOL.md, Trusted keys).
type TrustedKeys struct {
	passkeys map[string]*TrustedKey
	policy   map[string]ed25519.PublicKey

	// Legacy is true for a {"v": 1, "keys": [...]} file without a serial.
	Legacy bool
	// OrganizationID is empty for a legacy file.
	OrganizationID string
	// Serial is 0 for a legacy file.
	Serial int
	// UpdateThreshold is how many different owners must approve the next
	// key set; 1 for a legacy file.
	UpdateThreshold int
	// IssuedAt is zero for a legacy file.
	IssuedAt time.Time
	// Raw holds the exact document bytes; Hash is their SHA-256.
	Raw  []byte
	Hash [32]byte
}

// KeySetKind is the kind of a key set document.
const KeySetKind = "bifrost.keyset"

type legacyKeysFile struct {
	V    int           `json:"v"`
	Keys []*TrustedKey `json:"keys"`
}

type keySetFile struct {
	V               int           `json:"v"`
	Kind            string        `json:"kind"`
	OrganizationID  string        `json:"organization_id"`
	Serial          int           `json:"serial"`
	UpdateThreshold int           `json:"update_threshold"`
	IssuedAt        string        `json:"issued_at"`
	Keys            []*TrustedKey `json:"keys"`
}

// LoadTrustedKeys reads and checks the trusted keys file.
func LoadTrustedKeys(path string) (*TrustedKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trusted keys: %w", err)
	}
	k, err := ParseTrustedKeys(data)
	if err != nil {
		return nil, fmt.Errorf("trusted keys %s: %w", path, err)
	}
	return k, nil
}

// ParseTrustedKeys parses a trusted keys file strictly: a key set document
// (kind bifrost.keyset), or the older {"v": 1, "keys": [...]} form, which
// loads as serial 0 with an update threshold of 1 and no organization. Any
// malformed key fails the whole file.
func ParseTrustedKeys(data []byte) (*TrustedKeys, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var probe struct {
		Kind *string `json:"kind"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.Kind != nil {
		return ParseKeySet(data)
	}
	var f legacyKeysFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, err
	}
	if f.V != 1 {
		return nil, fmt.Errorf("unsupported version %d", f.V)
	}
	tk, err := buildKeys(f.Keys)
	if err != nil {
		return nil, err
	}
	tk.Legacy, tk.UpdateThreshold = true, 1
	tk.Raw, tk.Hash = append([]byte(nil), data...), sha256.Sum256(data)
	return tk, nil
}

// ParseKeySet parses a key set document strictly, the same way as an
// envelope: no duplicate keys, no unknown fields, v 1 and kind
// bifrost.keyset. It checks that every key is well-formed, not that the set
// is usable (see Usable).
func ParseKeySet(data []byte) (*TrustedKeys, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var f keySetFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, err
	}
	if f.V != 1 {
		return nil, fmt.Errorf("unsupported version %d", f.V)
	}
	if f.Kind != KeySetKind {
		return nil, fmt.Errorf("kind is %q, want %s", f.Kind, KeySetKind)
	}
	if f.OrganizationID == "" {
		return nil, errors.New("organization_id is required")
	}
	if f.Serial < 1 {
		return nil, fmt.Errorf("serial %d is not a positive integer", f.Serial)
	}
	issued, err := time.Parse(time.RFC3339, f.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("issued_at: %w", err)
	}
	tk, err := buildKeys(f.Keys)
	if err != nil {
		return nil, err
	}
	tk.OrganizationID, tk.Serial, tk.UpdateThreshold, tk.IssuedAt = f.OrganizationID, f.Serial, f.UpdateThreshold, issued
	tk.Raw, tk.Hash = append([]byte(nil), data...), sha256.Sum256(data)
	return tk, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// buildKeys checks each key and indexes them. A key_id appears once in the
// whole set, whatever its kind.
func buildKeys(keys []*TrustedKey) (*TrustedKeys, error) {
	tk := &TrustedKeys{passkeys: map[string]*TrustedKey{}, policy: map[string]ed25519.PublicKey{}}
	for i, k := range keys {
		if k == nil || k.KeyID == "" {
			return nil, fmt.Errorf("keys[%d]: key_id is required", i)
		}
		if _, dup := tk.passkeys[k.KeyID]; dup {
			return nil, fmt.Errorf("keys[%d]: duplicate key_id", i)
		}
		if _, dup := tk.policy[k.KeyID]; dup {
			return nil, fmt.Errorf("keys[%d]: duplicate key_id", i)
		}
		raw, err := DecodeB64U(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: public_key: %w", i, err)
		}
		switch k.Kind {
		case "passkey":
			if _, err := DecodeB64U(k.KeyID); err != nil {
				return nil, fmt.Errorf("keys[%d]: key_id is not base64url", i)
			}
			if k.Owner == "" || k.RPID == "" {
				return nil, fmt.Errorf("keys[%d]: owner and rp_id are required", i)
			}
			if err := checkOrigin(k.Origin); err != nil {
				return nil, fmt.Errorf("keys[%d]: %w", i, err)
			}
			pub, err := parsePasskeyPublicKey(k.Alg, raw)
			if err != nil {
				return nil, fmt.Errorf("keys[%d]: %w", i, err)
			}
			k.pub = pub
			tk.passkeys[k.KeyID] = k
		case "policy":
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("keys[%d]: policy key must be a raw 32-byte Ed25519 key", i)
			}
			tk.policy[k.KeyID] = ed25519.PublicKey(raw)
		default:
			return nil, fmt.Errorf("keys[%d]: unknown kind %q", i, k.Kind)
		}
	}
	return tk, nil
}

func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("origin %q is not a bare origin", origin)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1") {
		return nil
	}
	return fmt.Errorf("origin %q must be https", origin)
}

func parsePasskeyPublicKey(alg int, spki []byte) (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("alg -7 needs a P-256 ECDSA key")
		}
	case AlgEdDSA:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("alg -8 needs an Ed25519 key")
		}
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("alg -257 needs an RSA key of at least 2048 bits")
		}
	default:
		return nil, fmt.Errorf("unsupported alg %d", alg)
	}
	return pub, nil
}

// Passkey returns the trusted passkey with key_id.
func (t *TrustedKeys) Passkey(keyID string) (*TrustedKey, bool) {
	k, ok := t.passkeys[keyID]
	return k, ok
}

// Policy returns the trusted policy key with key_id.
func (t *TrustedKeys) Policy(keyID string) (ed25519.PublicKey, bool) {
	k, ok := t.policy[keyID]
	return k, ok
}

// Len is the number of keys in the set, passkeys and policy keys.
func (t *TrustedKeys) Len() int { return len(t.passkeys) + len(t.policy) }

// PasskeyCount is the number of passkeys in the set.
func (t *TrustedKeys) PasskeyCount() int { return len(t.passkeys) }

// Owners returns the distinct owners of the set's passkeys, sorted.
func (t *TrustedKeys) Owners() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range t.passkeys {
		if !seen[k.Owner] {
			seen[k.Owner] = true
			out = append(out, k.Owner)
		}
	}
	sort.Strings(out)
	return out
}

// Usable reports whether the set can be trusted as the next key set: at
// least one passkey, and an update threshold between 1 and the number of
// different owners (update check 4; parsing has checked each key).
func (t *TrustedKeys) Usable() error {
	if len(t.passkeys) == 0 {
		return errors.New("the key set has no passkey")
	}
	if owners := len(t.Owners()); t.UpdateThreshold < 1 || t.UpdateThreshold > owners {
		return fmt.Errorf("update_threshold %d must be between 1 and the number of different owners (%d)", t.UpdateThreshold, owners)
	}
	return nil
}
