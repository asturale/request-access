// Package host is the host side: enrollment, the PAM check and the local
// grant cache.
package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/asturale/request-access/internal/proto"
)

// Paths can be moved with environment variables, which only the tests use:
// PAM runs the binary with a clean environment.
var (
	ConfigDir = envOr("REQUEST_ACCESS_CONFIG_DIR", "/etc/request-access")
	StateDir  = envOr("REQUEST_ACCESS_STATE_DIR", "/var/lib/request-access")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Config is /etc/request-access/config.json.
type Config struct {
	URL       string `json:"url"`
	Name      string `json:"name"`
	ServerKey string `json:"server_key"`
	// Users that never need approval (for example a restricted service
	// account used by automation): "user" for every service, or
	// "service:user" (e.g. "sudo:root") for one service only.
	ExemptUsers []string `json:"exempt_users,omitempty"`
	// Maps PAM service names to the service shown and windowed on the
	// server. Unlisted PAM services fall back to their own name.
	Services map[string]string `json:"services,omitempty"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func configPath() string { return filepath.Join(ConfigDir, "config.json") }
func keyPath() string    { return filepath.Join(ConfigDir, "host.key") }

func LoadConfig() (*Config, ed25519.PrivateKey, ed25519.PublicKey, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, nil, nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", configPath(), err)
	}
	seed, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := proto.DecodeSeed(string(seed))
	if err != nil {
		return nil, nil, nil, err
	}
	srv, err := proto.DecodePublicKey(c.ServerKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("server_key: %w", err)
	}
	return &c, key, srv, nil
}

func SaveConfig(c *Config) error {
	if err := os.MkdirAll(ConfigDir, 0o755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(configPath(), append(data, '\n'), 0o644)
}

func (c *Config) Client(key ed25519.PrivateKey) *proto.Client {
	return &proto.Client{BaseURL: c.URL, KeyID: "host:" + c.Name, Key: key}
}

// Exempt reports whether user needs no approval for service. sudo started
// by root is always exempt: root already has every right sudo could grant,
// and gating it would only stall root cron jobs. Root SSH logins are not.
func (c *Config) Exempt(service, user string) bool {
	if service == "sudo" && user == "root" {
		return true
	}
	return slices.Contains(c.ExemptUsers, user) || slices.Contains(c.ExemptUsers, service+":"+user)
}

func (c *Config) ServiceFor(pamService string) string {
	if s, ok := c.Services[pamService]; ok {
		return s
	}
	switch pamService {
	case "sshd":
		return "ssh"
	case "sudo", "sudo-i":
		return "sudo"
	}
	return pamService
}

// ---------------------------------------------------------------- enroll

type EnrollOptions struct {
	URL       string
	Name      string
	ServerKey string // optional pin; fetched from the server when empty
	Out       func(format string, a ...any)
}

// Enroll creates a host key (if missing), asks the server to add this host
// and waits until the approver confirms on Telegram.
func Enroll(o EnrollOptions) error {
	if !nameRE.MatchString(o.Name) {
		return errors.New("host name may only contain letters, digits, '.', '_' and '-'")
	}
	unsigned := &proto.Client{BaseURL: o.URL}
	var info struct {
		Name      string `json:"name"`
		WorkerKey string `json:"worker_key"`
	}
	if err := unsigned.Do("GET", "/v1/info", nil, &info); err != nil {
		return fmt.Errorf("cannot reach %s: %w", o.URL, err)
	}
	if info.Name != "request-access" {
		return errors.New("that URL is not a Request Access server")
	}
	if o.ServerKey != "" && o.ServerKey != info.WorkerKey {
		return errors.New("the server key does not match the one you passed with --server-key")
	}
	srvKey, err := proto.DecodePublicKey(info.WorkerKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(ConfigDir, 0o755); err != nil {
		return err
	}
	var priv ed25519.PrivateKey
	if seed, err := os.ReadFile(keyPath()); err == nil {
		if priv, err = proto.DecodeSeed(string(seed)); err != nil {
			return err
		}
	} else {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(keyPath(), []byte(proto.EncodeSeed(priv)+"\n"), 0o600); err != nil {
			return err
		}
	}
	pub := priv.Public().(ed25519.PublicKey)

	var res struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := unsigned.Do("POST", "/v1/enroll", map[string]string{
		"name": o.Name, "key": proto.EncodeKey(pub), "nonce": proto.Nonce(),
	}, &res); err != nil {
		return err
	}
	if res.Fingerprint != proto.Fingerprint(pub) {
		return errors.New("server reported a different key fingerprint; aborting")
	}
	o.Out("Server key:      %s\n", proto.Fingerprint(srvKey))
	o.Out("This host's key: %s\n", res.Fingerprint)
	o.Out("Approve the enrollment on Telegram after checking the fingerprint matches.\n")
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		var st struct {
			Status string `json:"status"`
		}
		if err := unsigned.Do("GET", "/v1/enroll/"+res.ID+"?wait=25", nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "approved":
			cfg := &Config{URL: o.URL, Name: o.Name, ServerKey: info.WorkerKey}
			if old, _, _, err := LoadConfig(); err == nil && old.URL == o.URL {
				cfg.ExemptUsers, cfg.Services = old.ExemptUsers, old.Services
			}
			if err := SaveConfig(cfg); err != nil {
				return err
			}
			o.Out("Enrolled as %q.\n", o.Name)
			return nil
		case "denied":
			return errors.New("enrollment was denied")
		case "expired":
			return errors.New("enrollment expired")
		}
	}
	return errors.New("timed out waiting for approval")
}

// ---------------------------------------------------------------- PAM check

// Request is one access attempt as PAM describes it.
type Request struct {
	PAMService string
	User       string
	RHost      string
	TTY        string
	Detail     string
}

// Decision is the outcome of Check.
type Decision struct {
	Allowed bool
	Reason  string
	Cached  bool
}

// Check decides whether the attempt may proceed: exempt user, a cached
// grant that is still valid, or a fresh approval on Telegram. Any error
// means "no" -- this fails closed.
func Check(r Request, out func(string)) Decision {
	cfg, key, srv, err := LoadConfig()
	if err != nil {
		return Decision{Reason: "not configured: " + err.Error()}
	}
	service := cfg.ServiceFor(r.PAMService)
	if cfg.Exempt(service, r.User) {
		return Decision{Allowed: true, Reason: "exempt user"}
	}
	now := time.Now()
	if g := loadGrant(srv, service, r.User); g != nil && g.Allows(cfg.Name, service, r.User, now) {
		return Decision{Allowed: true, Reason: "cached grant", Cached: true}
	}

	client := cfg.Client(key)
	nonce := proto.Nonce()
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	err = client.Do("POST", "/v1/access", map[string]string{
		"service": service, "user": r.User, "rhost": r.RHost, "tty": r.TTY,
		"detail": r.Detail, "nonce": nonce,
	}, &created)
	if err != nil {
		return Decision{Reason: "request failed: " + err.Error()}
	}
	out("Request Access: waiting for approval on Telegram...")
	deadline := time.Unix(created.Expires, 0).Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var st struct {
			Status string             `json:"status"`
			Grant  *proto.SignedGrant `json:"grant"`
		}
		if err := client.Do("GET", "/v1/access/"+created.ID+"?wait=20", nil, &st); err != nil {
			return Decision{Reason: "status failed: " + err.Error()}
		}
		switch st.Status {
		case "pending":
			continue
		case "approved":
			if st.Grant == nil {
				return Decision{Reason: "approved without grant"}
			}
			g, err := st.Grant.Verify(srv)
			if err != nil {
				return Decision{Reason: err.Error()}
			}
			if g.Nonce != nonce || g.ID != created.ID || !g.Allows(cfg.Name, service, r.User, time.Now()) {
				return Decision{Reason: "grant does not match this request"}
			}
			if !g.Once {
				_ = saveGrant(service, r.User, *st.Grant)
			}
			return Decision{Allowed: true, Reason: "approved"}
		default:
			return Decision{Reason: st.Status}
		}
	}
	return Decision{Reason: "timed out"}
}

// ---------------------------------------------------------------- grant cache

var safeRE = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func grantPath(service, user string) string {
	return filepath.Join(StateDir, "grants", safeRE.ReplaceAllString(service, "_")+"__"+safeRE.ReplaceAllString(user, "_")+".json")
}

func loadGrant(srv ed25519.PublicKey, service, user string) *proto.Grant {
	data, err := os.ReadFile(grantPath(service, user))
	if err != nil {
		return nil
	}
	var sg proto.SignedGrant
	if json.Unmarshal(data, &sg) != nil {
		return nil
	}
	g, err := sg.Verify(srv)
	if err != nil {
		return nil
	}
	return g
}

func saveGrant(service, user string, sg proto.SignedGrant) error {
	dir := filepath.Join(StateDir, "grants")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(sg)
	return writeFileAtomic(grantPath(service, user), data, 0o600)
}

// CachedGrant is one entry of the local grant cache, for `status`.
type CachedGrant struct {
	Service, User string
	Expires       time.Time
	Valid         bool
}

func ListGrants() ([]CachedGrant, error) {
	cfg, _, srv, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	files, _ := filepath.Glob(filepath.Join(StateDir, "grants", "*.json"))
	var out []CachedGrant
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var sg proto.SignedGrant
		if json.Unmarshal(data, &sg) != nil {
			continue
		}
		g, err := sg.Verify(srv)
		if err != nil {
			continue
		}
		out = append(out, CachedGrant{
			Service: g.Service, User: g.User, Expires: time.Unix(g.Expires, 0),
			Valid: g.Allows(cfg.Name, g.Service, g.User, time.Now()),
		})
	}
	return out, nil
}

// Revoke removes cached grants; empty arguments match everything.
func Revoke(service, user string) (int, error) {
	files, _ := filepath.Glob(filepath.Join(StateDir, "grants", "*.json"))
	n := 0
	for _, f := range files {
		base := strings.TrimSuffix(filepath.Base(f), ".json")
		s, u, _ := strings.Cut(base, "__")
		if (service == "" || s == safeRE.ReplaceAllString(service, "_")) && (user == "" || u == safeRE.ReplaceAllString(user, "_")) {
			if err := os.Remove(f); err == nil {
				n++
			}
		}
	}
	return n, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
