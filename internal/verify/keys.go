package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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

// TrustedKeys is the parsed trusted keys file.
type TrustedKeys struct {
	passkeys map[string]*TrustedKey
	policy   map[string]ed25519.PublicKey
}

type keysFile struct {
	V    int           `json:"v"`
	Keys []*TrustedKey `json:"keys"`
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

// ParseTrustedKeys parses the trusted keys file strictly: any malformed key
// fails the whole file.
func ParseTrustedKeys(data []byte) (*TrustedKeys, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var f keysFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if f.V != 1 {
		return nil, fmt.Errorf("unsupported version %d", f.V)
	}
	tk := &TrustedKeys{passkeys: map[string]*TrustedKey{}, policy: map[string]ed25519.PublicKey{}}
	for i, k := range f.Keys {
		if k == nil || k.KeyID == "" {
			return nil, fmt.Errorf("keys[%d]: key_id is required", i)
		}
		raw, err := DecodeB64U(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: public_key: %w", i, err)
		}
		switch k.Kind {
		case "passkey":
			if _, dup := tk.passkeys[k.KeyID]; dup {
				return nil, fmt.Errorf("keys[%d]: duplicate passkey key_id", i)
			}
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
			if _, dup := tk.policy[k.KeyID]; dup {
				return nil, fmt.Errorf("keys[%d]: duplicate policy key_id", i)
			}
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
