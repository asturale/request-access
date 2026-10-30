// Package passkey verifies WebAuthn (passkey) registrations and assertions
// on the host itself, so an approval can be checked against a key that only
// the approver's phone holds. The server merely relays the signed data: a
// server that is compromised (or a stolen Cloudflare token that replaced it)
// cannot produce a valid assertion.
//
// Only what Request Access needs is implemented: "none" attestation (the
// public key is taken on first use, like the host's server key at
// enrollment), ES256, EdDSA and RS256 signatures, user presence and user
// verification required.
package passkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var b64 = base64.RawURLEncoding

// COSE algorithm identifiers.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified (biometrics or device PIN)
)

// Credential is a registered passkey as pinned in the host configuration.
type Credential struct {
	Label string `json:"label"`
	ID    string `json:"id"`  // credential id, base64url
	Alg   int    `json:"alg"` // COSE algorithm
	Key   string `json:"key"` // SubjectPublicKeyInfo DER, base64url
	Added int64  `json:"added,omitempty"`
}

// RP is the relying party the passkeys are bound to: the server's host name
// and origin. A passkey only signs for the domain it was created on.
type RP struct {
	ID     string `json:"rp_id"`
	Origin string `json:"origin"`
}

// RPForURL derives the relying party from the server URL. Browsers only
// allow passkeys on https sites (and on http://localhost, for testing).
func RPForURL(s string) (RP, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Hostname() == "" {
		return RP{}, errors.New("passkeys: bad server URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost") {
		return RP{}, errors.New("passkeys need an https server URL")
	}
	return RP{ID: u.Hostname(), Origin: u.Scheme + "://" + u.Host}, nil
}

// Challenge returns a fresh random registration challenge.
func Challenge() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}

// RequestChallenge binds an approval to one access request and to the
// approver's choice ("window" or "once"): the host computes it from values
// it chose itself, so the signature cannot be reused for anything else.
func RequestChallenge(host, service, user, nonce, choice string) string {
	h := sha256.New()
	for _, s := range []string{"request-access passkey v1", host, service, user, nonce, choice} {
		fmt.Fprintf(h, "%d:%s\n", len(s), s)
	}
	return b64.EncodeToString(h.Sum(nil))
}

// Registration is what the browser returns from navigator.credentials.create,
// as relayed by the server.
type Registration struct {
	ID             string `json:"id"`
	Alg            int    `json:"alg"`
	PublicKey      string `json:"public_key"` // SPKI DER from getPublicKey(), base64url
	ClientDataJSON string `json:"client_data_json"`
}

// Assertion is what the browser returns from navigator.credentials.get.
type Assertion struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func parseClientData(s, typ string, rp RP) (*clientData, []byte, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, nil, errors.New("passkey: bad client data encoding")
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, nil, errors.New("passkey: bad client data")
	}
	if cd.Type != typ {
		return nil, nil, fmt.Errorf("passkey: client data type %q, want %q", cd.Type, typ)
	}
	if cd.Origin != rp.Origin {
		return nil, nil, fmt.Errorf("passkey: origin %q, want %q", cd.Origin, rp.Origin)
	}
	return &cd, raw, nil
}

// VerifyRegistration checks a new passkey's client data against the
// challenge the host chose and returns the credential to pin.
//
// With "none" attestation nothing proves where the key lives, so this is
// trust on first use: register while you trust the server, and copy the
// result to other hosts with `passkey add --import` instead of registering
// again on each one.
func VerifyRegistration(r Registration, rp RP, challenge, label string) (*Credential, error) {
	cd, _, err := parseClientData(r.ClientDataJSON, "webauthn.create", rp)
	if err != nil {
		return nil, err
	}
	if cd.Challenge != challenge {
		return nil, errors.New("passkey: challenge does not match")
	}
	c := &Credential{Label: label, ID: r.ID, Alg: r.Alg, Key: r.PublicKey}
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Credential) check() error {
	if id, err := b64.DecodeString(c.ID); err != nil || len(id) == 0 || len(id) > 1023 {
		return errors.New("passkey: bad credential id")
	}
	_, err := c.publicKey()
	return err
}

func (c *Credential) publicKey() (crypto.PublicKey, error) {
	der, err := b64.DecodeString(c.Key)
	if err != nil {
		return nil, errors.New("passkey: bad public key encoding")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("passkey: bad public key: %w", err)
	}
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = c.Alg == AlgES256 && k.Curve.Params().Name == "P-256"
	case ed25519.PublicKey:
		ok = c.Alg == AlgEdDSA
	case *rsa.PublicKey:
		ok = c.Alg == AlgRS256 && k.N.BitLen() >= 2048
	}
	if !ok {
		return nil, fmt.Errorf("passkey: unsupported key type for algorithm %d", c.Alg)
	}
	return pub, nil
}

// Fingerprint identifies a credential's public key, for comparing across
// hosts.
func (c *Credential) Fingerprint() string {
	der, _ := b64.DecodeString(c.Key)
	h := sha256.Sum256(der)
	return "SHA256:" + b64.EncodeToString(h[:])
}

// Export / Import move a pinned credential between hosts as one line.
func (c *Credential) Export() string {
	data, _ := json.Marshal(Credential{Label: c.Label, ID: c.ID, Alg: c.Alg, Key: c.Key})
	return "ra-passkey:" + b64.EncodeToString(data)
}

func Import(line string) (*Credential, error) {
	s, ok := strings.CutPrefix(strings.TrimSpace(line), "ra-passkey:")
	if !ok {
		return nil, errors.New("not an exported passkey (should start with ra-passkey:)")
	}
	data, err := b64.DecodeString(s)
	if err != nil {
		return nil, errors.New("exported passkey: bad encoding")
	}
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, errors.New("exported passkey: bad content")
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyAssertion checks an approval: signed by one of the pinned
// credentials, for this relying party, with user verification, over one of
// the accepted challenges. It returns the challenge that was signed and the
// credential that signed it.
func VerifyAssertion(a Assertion, rp RP, creds []Credential, challenges []string) (string, *Credential, error) {
	var cred *Credential
	for i := range creds {
		if creds[i].ID == a.ID {
			cred = &creds[i]
			break
		}
	}
	if cred == nil {
		return "", nil, errors.New("passkey: not a registered passkey")
	}
	cd, rawCD, err := parseClientData(a.ClientDataJSON, "webauthn.get", rp)
	if err != nil {
		return "", nil, err
	}
	matched := ""
	for _, ch := range challenges {
		if ch != "" && cd.Challenge == ch {
			matched = ch
		}
	}
	if matched == "" {
		return "", nil, errors.New("passkey: signed for a different request")
	}
	authData, err := b64.DecodeString(a.AuthenticatorData)
	if err != nil || len(authData) < 37 {
		return "", nil, errors.New("passkey: bad authenticator data")
	}
	rpHash := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		return "", nil, errors.New("passkey: signed for a different site")
	}
	if authData[32]&flagUP == 0 || authData[32]&flagUV == 0 {
		return "", nil, errors.New("passkey: user was not verified")
	}
	sig, err := b64.DecodeString(a.Signature)
	if err != nil {
		return "", nil, errors.New("passkey: bad signature encoding")
	}
	pub, err := cred.publicKey()
	if err != nil {
		return "", nil, err
	}
	cdHash := sha256.Sum256(rawCD)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(k, digest[:], sig)
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, signed, sig)
	case *rsa.PublicKey:
		ok = rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	}
	if !ok {
		return "", nil, errors.New("passkey: signature does not verify")
	}
	return matched, cred, nil
}
