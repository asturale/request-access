package passkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
)

var rp = RP{ID: "ra.example.workers.dev", Origin: "https://ra.example.workers.dev"}

// authenticator is a software passkey.
type authenticator struct {
	id   string
	priv *ecdsa.PrivateKey
}

func newAuthenticator(t *testing.T) *authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{id: b64.EncodeToString([]byte("cred-" + t.Name())), priv: k}
}

func clientDataFor(typ, challenge, origin string) string {
	data, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b64.EncodeToString(data)
}

func (a *authenticator) register(t *testing.T, challenge string) Registration {
	der, err := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Registration{ID: a.id, Alg: AlgES256, PublicKey: b64.EncodeToString(der), ClientDataJSON: clientDataFor("webauthn.create", challenge, rp.Origin)}
}

func (a *authenticator) sign(t *testing.T, rpID, origin, challenge string, flags byte) Assertion {
	h := sha256.Sum256([]byte(rpID))
	authData := append(h[:], flags, 0, 0, 0, 0)
	cd := clientDataFor("webauthn.get", challenge, origin)
	raw, _ := b64.DecodeString(cd)
	cdHash := sha256.Sum256(raw)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{ID: a.id, ClientDataJSON: cd, AuthenticatorData: b64.EncodeToString(authData), Signature: b64.EncodeToString(sig)}
}

func TestRegisterAndApprove(t *testing.T) {
	a := newAuthenticator(t)
	ch := Challenge()
	cred, err := VerifyRegistration(a.register(t, ch), rp, ch, "phone")
	if err != nil {
		t.Fatal(err)
	}
	creds := []Credential{*cred}
	win := RequestChallenge("web1", "sudo", "alice", "n1", "window")
	once := RequestChallenge("web1", "sudo", "alice", "n1", "once")

	got, c, err := VerifyAssertion(a.sign(t, rp.ID, rp.Origin, once, flagUP|flagUV), rp, creds, []string{win, once})
	if err != nil || got != once || c.Label != "phone" {
		t.Fatalf("valid assertion: %q %v", got, err)
	}

	bad := map[string]Assertion{
		"other request":   a.sign(t, rp.ID, rp.Origin, RequestChallenge("web1", "sudo", "alice", "n2", "window"), flagUP|flagUV),
		"other host":      a.sign(t, rp.ID, rp.Origin, RequestChallenge("web2", "sudo", "alice", "n1", "window"), flagUP|flagUV),
		"other rp":        a.sign(t, "evil.example", rp.Origin, win, flagUP|flagUV),
		"other origin":    a.sign(t, rp.ID, "https://evil.example", win, flagUP|flagUV),
		"no verification": a.sign(t, rp.ID, rp.Origin, win, flagUP),
	}
	other := newAuthenticator(t)
	other.id = a.id // same id, different key
	bad["wrong key"] = other.sign(t, rp.ID, rp.Origin, win, flagUP|flagUV)
	tampered := a.sign(t, rp.ID, rp.Origin, win, flagUP|flagUV)
	tampered.ClientDataJSON = clientDataFor("webauthn.get", once, rp.Origin)
	bad["swapped choice"] = tampered
	unknown := a.sign(t, rp.ID, rp.Origin, win, flagUP|flagUV)
	unknown.ID = b64.EncodeToString([]byte("someone-else"))
	bad["unknown credential"] = unknown
	for name, as := range bad {
		if _, _, err := VerifyAssertion(as, rp, creds, []string{win, once}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRegistrationChecks(t *testing.T) {
	a := newAuthenticator(t)
	ch := Challenge()
	if _, err := VerifyRegistration(a.register(t, Challenge()), rp, ch, "x"); err == nil {
		t.Error("wrong challenge accepted")
	}
	r := a.register(t, ch)
	r.ClientDataJSON = clientDataFor("webauthn.get", ch, rp.Origin)
	if _, err := VerifyRegistration(r, rp, ch, "x"); err == nil {
		t.Error("assertion accepted as registration")
	}
	r = a.register(t, ch)
	r.Alg = AlgEdDSA
	if _, err := VerifyRegistration(r, rp, ch, "x"); err == nil {
		t.Error("algorithm/key mismatch accepted")
	}
}

func TestEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	cred := Credential{ID: "aWQ", Alg: AlgEdDSA, Key: b64.EncodeToString(der)}
	ch := RequestChallenge("h", "ssh", "u", "n", "window")
	h := sha256.Sum256([]byte(rp.ID))
	authData := append(h[:], flagUP|flagUV, 0, 0, 0, 1)
	cd := clientDataFor("webauthn.get", ch, rp.Origin)
	raw, _ := b64.DecodeString(cd)
	cdHash := sha256.Sum256(raw)
	sig := ed25519.Sign(priv, append(append([]byte{}, authData...), cdHash[:]...))
	as := Assertion{ID: "aWQ", ClientDataJSON: cd, AuthenticatorData: b64.EncodeToString(authData), Signature: b64.EncodeToString(sig)}
	if _, _, err := VerifyAssertion(as, rp, []Credential{cred}, []string{ch}); err != nil {
		t.Fatal(err)
	}
}

func TestExportImport(t *testing.T) {
	a := newAuthenticator(t)
	ch := Challenge()
	cred, err := VerifyRegistration(a.register(t, ch), rp, ch, "phone")
	if err != nil {
		t.Fatal(err)
	}
	line := cred.Export()
	if !strings.HasPrefix(line, "ra-passkey:") {
		t.Fatal(line)
	}
	got, err := Import(line)
	if err != nil || got.ID != cred.ID || got.Key != cred.Key || got.Fingerprint() != cred.Fingerprint() {
		t.Fatalf("import: %v", err)
	}
	if _, err := Import("ra-passkey:" + b64.EncodeToString([]byte(`{"id":"aWQ","alg":-7,"key":"AAAA"}`))); err == nil {
		t.Error("garbage key imported")
	}
}

func TestRPForURL(t *testing.T) {
	r, err := RPForURL("https://ra.example.workers.dev/")
	if err != nil || r != rp {
		t.Fatalf("%v %v", r, err)
	}
	if r, _ := RPForURL("http://localhost:8787"); r != (RP{ID: "localhost", Origin: "http://localhost:8787"}) {
		t.Errorf("localhost: %v", r)
	}
	for _, u := range []string{"http://x.dev", "http://127.0.0.1:8787", "ftp://x.dev"} {
		if _, err := RPForURL(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}
