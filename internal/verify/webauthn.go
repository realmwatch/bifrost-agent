package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
)

// Approval is one item of an execution's approvals.
type Approval struct {
	Kind              string `json:"kind"`
	KeyID             string `json:"key_id"`
	AuthenticatorData string `json:"authenticator_data,omitempty"`
	ClientDataJSON    string `json:"client_data_json,omitempty"`
	Signature         string `json:"signature"`
}

// Authenticator data flags.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// VerifyPasskey checks one WebAuthn assertion over the envelope hash
// against a trusted key.
func VerifyPasskey(k *TrustedKey, a Approval, hash [32]byte) error {
	cdj, err := DecodeB64U(a.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("client_data_json: %w", err)
	}
	authData, err := DecodeB64U(a.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("authenticator_data: %w", err)
	}
	sig, err := DecodeB64U(a.Signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return fmt.Errorf("client_data_json: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("client data type is %q, want webauthn.get", cd.Type)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(B64U(hash[:]))) != 1 {
		return errors.New("challenge does not match the envelope hash")
	}
	if cd.Origin != k.Origin {
		return fmt.Errorf("origin %q is not the key's origin", cd.Origin)
	}
	if cd.CrossOrigin {
		return errors.New("cross-origin assertion")
	}

	if len(authData) < 37 {
		return errors.New("authenticator_data is too short")
	}
	rpHash := sha256.Sum256([]byte(k.RPID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		return errors.New("rp_id hash does not match")
	}
	flags := authData[32]
	if flags&flagUserPresent == 0 {
		return errors.New("user presence flag not set")
	}
	if flags&flagUserVerified == 0 {
		return errors.New("user verification flag not set")
	}

	cdHash := sha256.Sum256(cdj)
	signed := make([]byte, 0, len(authData)+len(cdHash))
	signed = append(append(signed, authData...), cdHash[:]...)
	if !verifySignature(k.Alg, k.pub, signed, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

func verifySignature(alg int, pub crypto.PublicKey, msg, sig []byte) bool {
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		d := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, d[:], sig)
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, msg, sig)
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		d := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig) == nil
	}
	return false
}

// VerifyPolicy checks a policy key's Ed25519 signature over the raw
// envelope bytes.
func VerifyPolicy(pub ed25519.PublicKey, a Approval, envelope []byte) error {
	sig, err := DecodeB64U(a.Signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(pub, envelope, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}
