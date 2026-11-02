// Package vault is the secrets vault: secrets are encrypted to a vault key
// whose private half exists only encrypted with the approver's vault
// password, and is unlocked in the approver's browser for one request at a
// time. Neither a host (not even root there) nor the Worker can read a secret
// on its own. See docs/VAULT.md.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

var b64 = base64.RawURLEncoding

// Box is a message sealed to a P-256 public key (ECIES): an ephemeral key,
// ECDH, HKDF-SHA256 and AES-256-GCM. The vault page does the same with
// WebCrypto.
type Box struct {
	V   int    `json:"v"`
	EPK string `json:"epk"` // ephemeral public key, uncompressed point
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

const hkdfInfo = "secrets-vault v1"

// SecretAAD and ReleaseAAD bind a ciphertext to what it is for, so a box
// cannot be passed off as another server's secret, another secret, or be
// delivered to another request.
func SecretAAD(host, name string) []byte {
	return []byte("secrets-vault secret v1\n" + host + "\n" + name)
}

func ReleaseAAD(nonce, name string) []byte {
	return []byte("secrets-vault release v1\n" + nonce + "\n" + name)
}

// HeldReleaseAAD is used instead of ReleaseAAD when the approver agreed to
// let the agent hold the secret on the terms the host asked for (see
// HoldTerms), so the Worker cannot turn a single release into a held one.
func HeldReleaseAAD(nonce, name, hold string) []byte {
	return []byte("secrets-vault release v2\n" + nonce + "\n" + name + "\n" + hold)
}

// HoldTerms is how a hold is signed and shown: seconds the agent may keep
// the secret between uses, and at most in total.
func HoldTerms(idle, max int64) string {
	if idle <= 0 {
		return ""
	}
	return fmt.Sprintf("idle=%d,max=%d", idle, max)
}

// RequestMessage is what a host signs when it asks for a secret. The vault
// page checks the signature against the host keys stored inside the locked
// vault key, so the Worker cannot change who receives the secret, or what
// the approver is shown. Fields are length-prefixed, so none can spill into
// the next. A request that asks for a hold (hold != "") is a v2 message
// with the hold terms as an extra field; without one it stays v1.
func RequestMessage(host, user, name, reason, detail, replyKey, nonce string, box *Box, hold string) []byte {
	h := sha256.Sum256([]byte(box.EPK + "." + box.IV + "." + box.CT))
	fields := []string{"secrets-vault request v1", host, user, name, reason, detail, replyKey, nonce, b64.EncodeToString(h[:])}
	if hold != "" {
		fields[0] = "secrets-vault request v2"
		fields = append(fields, hold)
	}
	var out []byte
	for _, f := range fields {
		out = fmt.Appendf(out, "%d:%s\n", len(f), f)
	}
	return out
}

// ParsePublicKey decodes a raw (uncompressed) P-256 public key.
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vault key: %w", err)
	}
	return ecdh.P256().NewPublicKey(raw)
}

// EncodePublicKey is the inverse of ParsePublicKey.
func EncodePublicKey(pub *ecdh.PublicKey) string { return b64.EncodeToString(pub.Bytes()) }

// Fingerprint is how a vault key is compared between the page and hosts.
func Fingerprint(pub string) string {
	raw, _ := b64.DecodeString(pub)
	h := sha256.Sum256(raw)
	return "SHA256:" + b64.EncodeToString(h[:])
}

func boxKey(shared, epk, recipient []byte) ([]byte, error) {
	salt := append(append([]byte{}, epk...), recipient...)
	return hkdf.Key(sha256.New, shared, salt, hkdfInfo, 32)
}

// Seal encrypts plaintext to pub.
func Seal(pub *ecdh.PublicKey, plaintext, aad []byte) (*Box, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	epk := eph.PublicKey().Bytes()
	key, err := boxKey(shared, epk, pub.Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, iv, plaintext, aad)
	return &Box{V: 1, EPK: b64.EncodeToString(epk), IV: b64.EncodeToString(iv), CT: b64.EncodeToString(ct)}, nil
}

// Open decrypts a box sealed to priv.
func Open(priv *ecdh.PrivateKey, b *Box, aad []byte) ([]byte, error) {
	if b == nil || b.V != 1 {
		return nil, errors.New("unsupported box")
	}
	epk, err := b64.DecodeString(b.EPK)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := boxKey(shared, epk, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	iv, err := b64.DecodeString(b.IV)
	if err != nil || len(iv) != gcm.NonceSize() {
		return nil, errors.New("bad iv")
	}
	ct, err := b64.DecodeString(b.CT)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, iv, ct, aad)
	if err != nil {
		return nil, errors.New("could not decrypt (wrong key, or tampered with)")
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
