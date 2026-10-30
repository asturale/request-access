package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSealOpen(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(EncodePublicKey(priv.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	box, err := Seal(pub, []byte("hunter2"), SecretAAD("web1", "db"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(priv, box, SecretAAD("web1", "db"))
	if err != nil || !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := Open(priv, box, SecretAAD("web1", "other")); err == nil {
		t.Fatal("opened with the wrong name")
	}
	if _, err := Open(priv, box, SecretAAD("web2", "db")); err == nil {
		t.Fatal("opened as another server's secret")
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := Open(other, box, SecretAAD("web1", "db")); err == nil {
		t.Fatal("opened with the wrong key")
	}
	box.CT = box.CT[:len(box.CT)-2] + "AA"
	if _, err := Open(priv, box, SecretAAD("web1", "db")); err == nil {
		t.Fatal("opened a tampered box")
	}
}
