// Package proto implements the wire protocol shared by hosts, the admin CLI
// and the server: Ed25519-signed requests and Ed25519-signed grants.
package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// EncodeKey returns the base64url form of a raw Ed25519 public key.
func EncodeKey(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

// DecodePublicKey parses a base64url raw Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	return ed25519.PublicKey(b), nil
}

// EncodeSeed / DecodeSeed store a private key as its 32-byte seed.
func EncodeSeed(priv ed25519.PrivateKey) string { return b64.EncodeToString(priv.Seed()) }

func DecodeSeed(s string) (ed25519.PrivateKey, error) {
	b, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("invalid private key")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// Fingerprint matches the Worker's fingerprint format.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "SHA256:" + b64.EncodeToString(h[:])
}

// Nonce returns a random base64url string suitable as a request nonce.
func Nonce() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}

// SigningMessage is what a signed request's RA-Signature covers.
func SigningMessage(method, pathAndQuery, ts string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("RA1\n" + method + "\n" + pathAndQuery + "\n" + ts + "\n" + b64.EncodeToString(h[:]))
}

// Client talks to a Request Access server.
type Client struct {
	BaseURL string
	KeyID   string // "host:<name>" or "admin:<n>"; empty for unsigned calls
	Key     ed25519.PrivateKey
	HTTP    *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 40 * time.Second}
}

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("server: %s (HTTP %d)", e.Message, e.Status) }

// Do sends a (signed, if a key is set) request and decodes the JSON answer.
func (c *Client) Do(method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "request-access")
	if c.Key != nil {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sig := ed25519.Sign(c.Key, SigningMessage(method, path, ts, body))
		req.Header.Set("RA-Key-Id", c.KeyID)
		req.Header.Set("RA-Timestamp", ts)
		req.Header.Set("RA-Signature", b64.EncodeToString(sig))
	}
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &APIError{Status: res.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// SignedGrant is a grant as transported: the exact payload bytes plus the
// server's signature over them.
type SignedGrant struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// Grant is the signed statement "the approver allowed <user> to use
// <service> on <host> until <exp>".
type Grant struct {
	V        int    `json:"v"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Host     string `json:"host"`
	Service  string `json:"service"`
	User     string `json:"user"`
	Nonce    string `json:"nonce"`
	Once     bool   `json:"once"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Verify checks the signature with the server key and returns the grant.
// It does not check expiry or who the grant is for; see Grant.Allows.
func (s SignedGrant) Verify(serverKey ed25519.PublicKey) (*Grant, error) {
	payload, err := b64.DecodeString(s.Payload)
	if err != nil {
		return nil, errors.New("grant: bad payload encoding")
	}
	sig, err := b64.DecodeString(s.Sig)
	if err != nil {
		return nil, errors.New("grant: bad signature encoding")
	}
	if !ed25519.Verify(serverKey, payload, sig) {
		return nil, errors.New("grant: signature does not verify")
	}
	var g Grant
	if err := json.Unmarshal(payload, &g); err != nil {
		return nil, errors.New("grant: bad payload")
	}
	if g.V != 1 || g.Kind != "grant" {
		return nil, errors.New("grant: unsupported version")
	}
	return &g, nil
}

// Allows reports whether the grant covers this host, service and user now.
func (g *Grant) Allows(host, service, user string, now time.Time) bool {
	return g.Host == host && g.Service == service && g.User == user &&
		now.Unix() < g.Expires && now.Unix() >= g.IssuedAt-MaxSkew
}

// MaxSkew is the clock difference tolerated between host and server.
const MaxSkew = 60
