package host

import (
	"testing"
	"time"

	"github.com/asturale/request-access/internal/proto"
)

func TestCachedGrantOnlyCoversItsSource(t *testing.T) {
	now := time.Now()
	cfg := &Config{Name: "web1"}
	c := &cachedGrant{
		RHost: "100.64.0.1",
		Grant: &proto.Grant{Host: "web1", Service: "ssh", User: "alice", IssuedAt: now.Unix(), Expires: now.Add(15 * time.Minute).Unix()},
	}

	if !c.usable(cfg, "ssh", "alice", "100.64.0.1", now) {
		t.Fatal("grant should cover the source it was approved for")
	}
	if c.usable(cfg, "ssh", "alice", "100.64.0.2", now) {
		t.Fatal("grant must not cover another source")
	}
	if c.usable(cfg, "ssh", "alice", "", now) {
		t.Fatal("grant for a remote source must not cover a local attempt")
	}

	// Grants cached before the source was recorded have no RHost: they keep
	// working for local services (sudo) but not for remote logins.
	old := &cachedGrant{Grant: &proto.Grant{Host: "web1", Service: "sudo", User: "alice", IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix()}}
	if !old.usable(cfg, "sudo", "alice", "", now) {
		t.Fatal("local grant should still work")
	}
	if old.usable(cfg, "sudo", "alice", "100.64.0.1", now) {
		t.Fatal("grant without a source must not cover a remote attempt")
	}
}
