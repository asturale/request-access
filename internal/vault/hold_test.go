package vault

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asturale/request-access/internal/host"
)

func TestHoldTerms(t *testing.T) {
	for _, c := range []struct {
		asked, maxHold, maxLease int64
		want                     string
	}{
		{0, 3600, 14400, ""},
		{1800, 0, 14400, ""},
		{1800, 3600, 14400, "idle=1800,max=14400"},
		{7200, 3600, 14400, "idle=3600,max=14400"},
	} {
		if _, _, got := holdTerms(c.asked, c.maxHold, c.maxLease); got != c.want {
			t.Errorf("holdTerms(%d, %d, %d) = %q, want %q", c.asked, c.maxHold, c.maxLease, got, c.want)
		}
	}
}

func TestHoldLimits(t *testing.T) {
	var none *host.VaultConfig
	if h, l := none.HoldLimits(); h != 0 || l != 0 {
		t.Fatalf("no vault: %d %d", h, l)
	}
	if h, l := (&host.VaultConfig{}).HoldLimits(); h != 3600 || l != 14400 {
		t.Fatalf("defaults: %d %d", h, l)
	}
	off, big, neg := int64(0), int64(1<<40), int64(-5)
	if h, _ := (&host.VaultConfig{MaxHold: &off}).HoldLimits(); h != 0 {
		t.Fatalf("off: %d", h)
	}
	if h, l := (&host.VaultConfig{MaxHold: &big, MaxLease: &big}).HoldLimits(); h != 43200 || l != 43200 {
		t.Fatalf("capped: %d %d", h, l)
	}
	if h, l := (&host.VaultConfig{MaxLease: &neg}).HoldLimits(); h != 0 || l != 0 {
		t.Fatalf("negative lease: %d %d", h, l)
	}
}

func TestHolds(t *testing.T) {
	var hs holds
	now := time.Now()
	k := holdKey{uid: 1000, name: "gh", commit: "c1", scope: "42@7"}
	secret := []byte("tok")
	hs.put(k, &heldSecret{value: secret, env: "GH_TOKEN", request: "r1", idle: 30 * time.Minute, until: now.Add(4 * time.Hour), lastUsed: now})

	if v, env, id, _, ok := hs.get(k, now.Add(20*time.Minute)); !ok || string(v) != "tok" || env != "GH_TOKEN" || id != "r1" {
		t.Fatalf("get: %q %q %q %v", v, env, id, ok)
	}
	// Use moved the idle window on.
	if _, _, _, _, ok := hs.get(k, now.Add(45*time.Minute)); !ok {
		t.Fatal("hold should still be live 25 min after last use")
	}
	for _, other := range []holdKey{
		{uid: 1001, name: "gh", commit: "c1", scope: "42@7"},
		{uid: 1000, name: "cf", commit: "c1", scope: "42@7"},
		{uid: 1000, name: "gh", commit: "c2", scope: "42@7"},
		{uid: 1000, name: "gh", commit: "c1", scope: "43@7"},
	} {
		if _, _, _, _, ok := hs.get(other, now); ok {
			t.Fatalf("hold served to %+v", other)
		}
	}
	// Idle too long: gone, and wiped.
	if _, _, _, _, ok := hs.get(k, now.Add(45*time.Minute+31*time.Minute)); ok {
		t.Fatal("idle hold served")
	}
	if !bytes.Equal(secret, make([]byte, 3)) {
		t.Fatalf("dropped secret not wiped: %q", secret)
	}

	// Total limit, however often it is used.
	hs.put(k, &heldSecret{value: []byte("x"), idle: time.Hour, until: now.Add(90 * time.Minute), lastUsed: now})
	for m := 50; m <= 100; m += 50 {
		_, _, _, _, ok := hs.get(k, now.Add(time.Duration(m)*time.Minute))
		if ok != (m < 90) {
			t.Fatalf("at %d min: ok=%v", m, ok)
		}
	}

	hs.put(k, &heldSecret{value: []byte("x"), idle: time.Hour, until: now.Add(time.Hour), lastUsed: now})
	_, _, _, gen, _ := hs.get(k, now)
	if !hs.still(k, gen, now) {
		t.Fatal("copy should still be servable")
	}
	hs.forget(1000, "gh")
	if hs.still(k, gen, now) {
		t.Fatal("copy of a forgotten hold is servable")
	}
	hs.put(k, &heldSecret{value: []byte("x"), idle: time.Hour, until: now.Add(time.Hour), lastUsed: now})
	if hs.still(k, gen, now) {
		t.Fatal("copy of a replaced hold is servable")
	}
	hs.put(holdKey{uid: 1000, name: "cf"}, &heldSecret{value: []byte("y"), idle: time.Hour, until: now.Add(time.Hour), lastUsed: now})
	hs.put(holdKey{uid: 1001, name: "gh"}, &heldSecret{value: []byte("z"), idle: time.Hour, until: now.Add(time.Hour), lastUsed: now})
	if n := hs.forget(1000, "gh"); n != 1 {
		t.Fatalf("forget one: %d", n)
	}
	if n := hs.forget(1000, ""); n != 1 {
		t.Fatalf("forget all: %d", n)
	}
	hs.sweep(now.Add(2 * time.Hour))
	if len(hs.m) != 0 {
		t.Fatalf("sweep left %d", len(hs.m))
	}
}

func TestSessionScope(t *testing.T) {
	a, b := sessionScope(int32(os.Getpid())), sessionScope(int32(os.Getpid()))
	if a != b {
		t.Fatalf("scope not stable: %q %q", a, b)
	}
	if a != "" && !strings.Contains(a, "@") {
		t.Fatalf("scope %q", a)
	}
	if sessionScope(1<<30) != "" {
		t.Fatal("scope for a missing process")
	}
}

func TestRequestMessageVersions(t *testing.T) {
	box := &Box{V: 1, EPK: "e", IV: "i", CT: "c"}
	v1 := RequestMessage("h", "u", "n", "r", "d", "k", "nonce", box, "")
	if !bytes.HasPrefix(v1, []byte("24:secrets-vault request v1\n")) {
		t.Fatalf("v1: %q", v1)
	}
	v2 := RequestMessage("h", "u", "n", "r", "d", "k", "nonce", box, "idle=1800,max=14400")
	if !bytes.HasPrefix(v2, []byte("24:secrets-vault request v2\n")) || !bytes.HasSuffix(v2, []byte("\n19:idle=1800,max=14400\n")) {
		t.Fatalf("v2: %q", v2)
	}
	if bytes.Equal(HeldReleaseAAD("n", "s", "idle=1,max=1"), ReleaseAAD("n", "s")) {
		t.Fatal("held and single release share AAD")
	}
}
