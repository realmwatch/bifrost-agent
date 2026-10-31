package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Host is one entry of the envelope's hosts.
type Host struct {
	ServerID  string `json:"server_id"`
	Name      string `json:"name"`
	MachineID string `json:"machine_id"`
}

// Step is one operation or rollback step.
type Step struct {
	Op      string `json:"op"`
	Version int    `json:"version"`
	// Params is the decoded params object (numbers as json.Number). It is
	// only safe to use after schema validation.
	Params map[string]any `json:"-"`
	// RawParams is the params value as it appears in the envelope.
	RawParams json.RawMessage `json:"params"`
}

// Key returns op@version.
func (s Step) Key() string { return fmt.Sprintf("%s@%d", s.Op, s.Version) }

// Envelope is the approved document, parsed from its exact bytes.
type Envelope struct {
	V              int     `json:"v"`
	Kind           string  `json:"kind"`
	ProposalID     string  `json:"proposal_id"`
	OrganizationID string  `json:"organization_id"`
	Hosts          []Host  `json:"hosts"`
	Operations     []Step  `json:"operations"`
	Rollback       []Step  `json:"rollback"`
	Irreversible   bool    `json:"irreversible"`
	Intent         string  `json:"intent"`
	RiskTier       string  `json:"risk_tier"`
	NotBefore      *string `json:"not_before"`
	ExpiresAt      string  `json:"expires_at"`
	Nonce          string  `json:"nonce"`

	// Raw holds the exact envelope bytes; Hash is their SHA-256.
	Raw  []byte   `json:"-"`
	Hash [32]byte `json:"-"`
	// Parsed times. NotBeforeTime is zero when not_before is null.
	NotBeforeTime time.Time `json:"-"`
	ExpiresAtTime time.Time `json:"-"`
}

// ErrDuplicateKey reports an object with the same key twice.
var ErrDuplicateKey = errors.New("duplicate JSON key")

// checkNoDuplicateKeys walks the JSON token stream and fails if any object,
// at any depth, repeats a key, or if anything follows the top-level value.
// Different JSON parsers keep the first or the last of a repeated key, so
// the approver app, the hub and the agent could otherwise read different
// envelopes from the same signed bytes.
func checkNoDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the envelope")
	}
	return nil
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kt.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("%w %q", ErrDuplicateKey, key)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}

// ParseEnvelope parses envelope bytes strictly: duplicate keys, unknown
// fields and malformed values are errors. It is check 1.
func ParseEnvelope(data []byte) (*Envelope, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, err
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}
	if env.V != 1 {
		return nil, fmt.Errorf("unsupported envelope version %d", env.V)
	}
	if env.Kind != "bifrost.envelope" {
		return nil, fmt.Errorf("kind is %q, want bifrost.envelope", env.Kind)
	}
	if len(env.Operations) == 0 {
		return nil, errors.New("no operations")
	}
	for i := range env.Operations {
		if err := decodeParams(&env.Operations[i]); err != nil {
			return nil, fmt.Errorf("operations[%d]: %w", i, err)
		}
	}
	for i := range env.Rollback {
		if err := decodeParams(&env.Rollback[i]); err != nil {
			return nil, fmt.Errorf("rollback[%d]: %w", i, err)
		}
	}
	exp, err := time.Parse(time.RFC3339, env.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("expires_at: %w", err)
	}
	env.ExpiresAtTime = exp
	if env.NotBefore != nil {
		nb, err := time.Parse(time.RFC3339, *env.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("not_before: %w", err)
		}
		env.NotBeforeTime = nb
	}
	env.Raw = append([]byte(nil), data...)
	env.Hash = sha256.Sum256(data)
	return &env, nil
}

func decodeParams(s *Step) error {
	if s.Op == "" || s.Version < 1 {
		return errors.New("op and version are required")
	}
	if len(s.RawParams) == 0 {
		return errors.New("params are required")
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(s.RawParams))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("params must be an object")
	}
	s.Params = m
	return nil
}

// B64U encodes base64url without padding.
func B64U(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeB64U decodes base64url, tolerating trailing padding.
func DecodeB64U(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
