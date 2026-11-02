// Package host is the host side: enrollment, the PAM check and the local
// grant cache.
package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/asturale/request-access/internal/passkey"
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
	// Passkeys whose signature this host checks itself (see
	// docs/PASSKEYS.md).
	Passkey *PasskeyConfig `json:"passkey,omitempty"`
	// Vault pins the secrets vault's public key (see docs/VAULT.md): new
	// secrets are encrypted to this key, never to one the server hands out.
	Vault *VaultConfig `json:"vault,omitempty"`
}

// VaultConfig is the pinned vault key.
type VaultConfig struct {
	Key string `json:"key"` // P-256 public key, raw, base64url
	// How long the agent may hold a released secret for the session that
	// asked (vault run/get --hold), in seconds: MaxHold between uses
	// (default 3600; 0 turns holding off), MaxLease in total (default 14400,
	// at most 43200).
	MaxHold  *int64 `json:"max_hold,omitempty"`
	MaxLease *int64 `json:"max_lease,omitempty"`
}

// HoldLimits returns the configured limits for holding released secrets.
func (v *VaultConfig) HoldLimits() (maxHold, maxLease int64) {
	maxHold, maxLease = 3600, 14400
	if v == nil {
		return 0, 0
	}
	if v.MaxHold != nil {
		maxHold = *v.MaxHold
	}
	if v.MaxLease != nil {
		maxLease = *v.MaxLease
	}
	if maxHold < 0 {
		maxHold = 0
	}
	// The Worker forgets a request a day after it was made, and with it
	// the record that lets the approver revoke a hold; stay well inside.
	maxLease = min(max(maxLease, 0), 43200)
	maxHold = min(maxHold, maxLease)
	return maxHold, maxLease
}

// PasskeyConfig pins the approvers' passkeys on this host.
type PasskeyConfig struct {
	passkey.RP
	// Required: only a passkey signature approves; taps on Telegram no
	// longer do. Without it, both work (useful while trying passkeys out).
	Required bool `json:"required"`
	// Window caps (in seconds) how long a passkey approval is cached here,
	// whatever the server says. Default 900.
	Window      int64                `json:"window,omitempty"`
	Credentials []passkey.Credential `json:"credentials"`
}

// maxWait bounds how long the PAM check waits for an answer; the server's
// request_timeout cannot exceed it.
const maxWait = 10*time.Minute + 5*time.Second

// pinned reports whether a credential id is still registered here.
func (p *PasskeyConfig) pinned(id string) bool {
	return p != nil && id != "" && slices.ContainsFunc(p.Credentials, func(c passkey.Credential) bool { return c.ID == id })
}

// active reports whether access requests should ask for a passkey.
func (p *PasskeyConfig) active() bool { return p != nil && (p.Required || len(p.Credentials) > 0) }

func (p *PasskeyConfig) window() int64 {
	if p.Window > 0 {
		return p.Window
	}
	return 900
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
				cfg.ExemptUsers, cfg.Services, cfg.Passkey = old.ExemptUsers, old.Services, old.Passkey
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
//
// With passkeys pinned, the approval must also carry a passkey signature
// over a challenge this host chose, verified here; when they are required,
// a grant signed by the server alone is not enough.
func Check(r Request, out func(string)) Decision {
	cfg, key, srv, err := LoadConfig()
	if err != nil {
		return Decision{Reason: "not configured: " + err.Error()}
	}
	service := cfg.ServiceFor(r.PAMService)
	if cfg.Exempt(service, r.User) {
		return Decision{Allowed: true, Reason: "exempt user"}
	}
	pk := cfg.Passkey
	required := pk != nil && pk.Required
	now := time.Now()
	if c := loadGrant(srv, service, r.User); c != nil && c.usable(cfg, service, r.User, r.RHost, now) {
		// Report the reuse first, so the approver sees it and can revoke the
		// window. Revoked: drop it and ask again. Server unreachable: the
		// window still counts, as it would without reports, so an outage
		// does not lock out someone holding a valid approval.
		switch err := reportReuse(cfg, key, c.Grant.ID, r); {
		case err == nil:
			return Decision{Allowed: true, Reason: "cached grant", Cached: true}
		case errors.Is(err, errRevoked):
			_ = os.Remove(grantPath(service, r.User))
		default:
			return Decision{Allowed: true, Reason: "cached grant (reuse not reported: " + err.Error() + ")", Cached: true}
		}
	}
	if required && len(pk.Credentials) == 0 {
		return Decision{Reason: "passkey required but none registered"}
	}

	client := cfg.Client(key)
	nonce := proto.Nonce()
	started := time.Now()
	body := map[string]any{
		"service": service, "user": r.User, "rhost": r.RHost, "tty": r.TTY,
		"detail": r.Detail, "nonce": nonce,
	}
	var chWindow, chOnce string
	if pk.active() {
		chWindow = passkey.RequestChallenge(cfg.Name, service, r.User, nonce, "window")
		chOnce = passkey.RequestChallenge(cfg.Name, service, r.User, nonce, "once")
		ids := make([]string, 0, len(pk.Credentials))
		for _, c := range pk.Credentials {
			ids = append(ids, c.ID)
		}
		body["passkey"] = map[string]any{
			"rp_id":       pk.ID,
			"challenges":  map[string]string{"window": chWindow, "once": chOnce},
			"credentials": ids,
			"required":    required,
		}
	}
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	if err := client.Do("POST", "/v1/access", body, &created); err != nil {
		return Decision{Reason: "request failed: " + err.Error()}
	}
	if pk.active() {
		out("Request Access: waiting for approval with your passkey (link on Telegram)...")
	} else {
		out("Request Access: waiting for approval on Telegram...")
	}
	// Never wait longer than the host allows, whatever the server says: a
	// server holding on to an approval must not be able to use it later.
	deadline := time.Unix(created.Expires, 0).Add(5 * time.Second)
	if limit := started.Add(maxWait); deadline.After(limit) {
		deadline = limit
	}
	for time.Now().Before(deadline) {
		var st struct {
			Status  string             `json:"status"`
			Grant   *proto.SignedGrant `json:"grant"`
			Passkey *passkey.Assertion `json:"passkey"`
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
			if !time.Now().Before(deadline) {
				return Decision{Reason: "timed out"}
			}
			g, err := st.Grant.Verify(srv)
			if err != nil {
				return Decision{Reason: err.Error()}
			}
			if g.Nonce != nonce || g.ID != created.ID || !g.Allows(cfg.Name, service, r.User, time.Now()) {
				return Decision{Reason: "grant does not match this request"}
			}
			c := cachedGrant{SignedGrant: *st.Grant, RHost: r.RHost}
			once := g.Once
			reason := "approved"
			if st.Passkey != nil && pk.active() {
				signed, cred, err := passkey.VerifyAssertion(*st.Passkey, pk.RP, pk.Credentials, []string{chWindow, chOnce})
				if err != nil {
					return Decision{Reason: err.Error()}
				}
				// The choice is part of what the passkey signed; the
				// window is this host's, not the server's.
				once = once || signed == chOnce
				c.Passkey = true
				c.Credential = cred.ID
				c.Until = started.Unix() + pk.window()
				reason = "approved with passkey " + cred.Label
			} else if required {
				return Decision{Reason: "approval has no passkey signature"}
			}
			if !once {
				_ = saveGrant(service, r.User, c)
			}
			return Decision{Allowed: true, Reason: reason}
		default:
			return Decision{Reason: st.Status}
		}
	}
	return Decision{Reason: "timed out"}
}

// ---------------------------------------------------------------- passkeys

// RegisterOptions starts a passkey registration from this host.
type RegisterOptions struct {
	Label string
	Out   func(format string, a ...any)
}

// RegisterPasskey asks the approver (via a link on Telegram) to create a
// passkey, then pins its public key in this host's configuration.
func RegisterPasskey(o RegisterOptions) (*passkey.Credential, error) {
	cfg, key, _, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	rp, err := passkey.RPForURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Passkey != nil && cfg.Passkey.ID != "" && cfg.Passkey.RP != rp {
		return nil, fmt.Errorf("the pinned passkeys belong to %s, but the server is now %s; remove them first", cfg.Passkey.ID, rp.ID)
	}
	var exclude []string
	if cfg.Passkey != nil {
		for _, c := range cfg.Passkey.Credentials {
			if c.Label == o.Label {
				return nil, fmt.Errorf("a passkey named %q is already registered", o.Label)
			}
			exclude = append(exclude, c.ID)
		}
	}
	challenge := passkey.Challenge()
	client := cfg.Client(key)
	var created struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}
	if err := client.Do("POST", "/v1/passkey/register", map[string]any{
		"label": o.Label, "challenge": challenge, "rp_id": rp.ID, "exclude": exclude, "nonce": proto.Nonce(),
	}, &created); err != nil {
		return nil, err
	}
	o.Out("Open the link on Telegram on your phone and create the passkey.\n")
	deadline := time.Unix(created.Expires, 0).Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var st struct {
			Status       string                `json:"status"`
			Registration *passkey.Registration `json:"registration"`
		}
		if err := client.Do("GET", "/v1/passkey/register/"+created.ID+"?wait=20", nil, &st); err != nil {
			return nil, err
		}
		switch st.Status {
		case "pending":
			continue
		case "approved":
			if st.Registration == nil {
				return nil, errors.New("server returned no passkey")
			}
			cred, err := passkey.VerifyRegistration(*st.Registration, rp, challenge, o.Label)
			if err != nil {
				return nil, err
			}
			cred.Added = time.Now().Unix()
			if err := AddPasskey(*cred); err != nil {
				return nil, err
			}
			return cred, nil
		default:
			return nil, fmt.Errorf("registration %s", st.Status)
		}
	}
	return nil, errors.New("timed out waiting for the passkey")
}

// AddPasskey pins a credential (registered here or exported from another
// host) in this host's configuration.
func AddPasskey(cred passkey.Credential) error {
	cfg, _, _, err := LoadConfig()
	if err != nil {
		return err
	}
	rp, err := passkey.RPForURL(cfg.URL)
	if err != nil {
		return err
	}
	if cfg.Passkey == nil {
		cfg.Passkey = &PasskeyConfig{}
	}
	if cfg.Passkey.ID != "" && cfg.Passkey.RP != rp {
		return fmt.Errorf("the pinned passkeys belong to %s, but the server is now %s", cfg.Passkey.ID, rp.ID)
	}
	cfg.Passkey.RP = rp
	for _, c := range cfg.Passkey.Credentials {
		if c.ID == cred.ID {
			return errors.New("this passkey is already registered here")
		}
		if c.Label == cred.Label {
			return fmt.Errorf("a passkey named %q is already registered", cred.Label)
		}
	}
	if cred.Added == 0 {
		cred.Added = time.Now().Unix()
	}
	cfg.Passkey.Credentials = append(cfg.Passkey.Credentials, cred)
	return SaveConfig(cfg)
}

// RemovePasskey unpins a credential by label. The last one cannot go while
// passkeys are required: that would lock everybody out.
func RemovePasskey(label string) error {
	cfg, _, _, err := LoadConfig()
	if err != nil {
		return err
	}
	if cfg.Passkey == nil {
		return errors.New("no passkeys registered")
	}
	i := slices.IndexFunc(cfg.Passkey.Credentials, func(c passkey.Credential) bool { return c.Label == label })
	if i < 0 {
		return fmt.Errorf("no passkey named %q", label)
	}
	if cfg.Passkey.Required && len(cfg.Passkey.Credentials) == 1 {
		return errors.New("this is the last passkey and passkeys are required; run `passkey require off` first")
	}
	cfg.Passkey.Credentials = slices.Delete(cfg.Passkey.Credentials, i, i+1)
	return SaveConfig(cfg)
}

// RequirePasskey switches between "passkey or tap" and "passkey only".
// Cached grants without a passkey stop counting as soon as it is on.
func RequirePasskey(on bool) error {
	cfg, _, _, err := LoadConfig()
	if err != nil {
		return err
	}
	if on && (cfg.Passkey == nil || len(cfg.Passkey.Credentials) == 0) {
		return errors.New("register a passkey first")
	}
	if cfg.Passkey == nil {
		return nil
	}
	cfg.Passkey.Required = on
	return SaveConfig(cfg)
}

// ---------------------------------------------------------------- grant cache

var errRevoked = errors.New("window revoked")

// reuseTimeout bounds how long a cached login or sudo waits for the report.
var reuseTimeout = 3 * time.Second

// reportReuse tells the server a cached window is used again. errRevoked
// if the approver revoked it; any other error means the report did not
// get through.
func reportReuse(cfg *Config, key ed25519.PrivateKey, id string, r Request) error {
	client := cfg.Client(key)
	client.HTTP = &http.Client{Timeout: reuseTimeout}
	var out struct {
		Status string `json:"status"`
	}
	err := client.Do("POST", "/v1/access/"+id+"/reused", map[string]any{
		"rhost": r.RHost, "tty": r.TTY, "detail": r.Detail, "nonce": proto.Nonce(),
	}, &out)
	if err != nil {
		return err
	}
	if out.Status == "revoked" {
		return errRevoked
	}
	return nil
}

var safeRE = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func grantPath(service, user string) string {
	return filepath.Join(StateDir, "grants", safeRE.ReplaceAllString(service, "_")+"__"+safeRE.ReplaceAllString(user, "_")+".json")
}

// cachedGrant is a grant file: the server's signed grant plus what this host
// itself verified (the directory is root-only, so these fields are trusted).
type cachedGrant struct {
	proto.SignedGrant
	Passkey bool  `json:"passkey,omitempty"` // approved with a verified passkey
	Until   int64 `json:"until,omitempty"`   // this host's own expiry, if any
	// The passkey that approved; the grant stops counting once it is unpinned.
	Credential string `json:"credential,omitempty"`
	// The remote host (PAM_RHOST) the approval was for; the grant only
	// counts for attempts from that same source. Empty for local services.
	RHost string       `json:"rhost,omitempty"`
	Grant *proto.Grant `json:"-"`
}

// usable reports whether a verified cached grant still lets this attempt in.
// It only covers the source it was approved for: approving a login from one
// machine must not let another one in during the window.
func (c *cachedGrant) usable(cfg *Config, service, user, rhost string, now time.Time) bool {
	pk := cfg.Passkey
	required := pk != nil && pk.Required
	return c.RHost == rhost && c.Grant.Allows(cfg.Name, service, user, now) &&
		(!required || c.Passkey) && (c.Until == 0 || now.Unix() < c.Until) &&
		(!c.Passkey || pk.pinned(c.Credential))
}

func loadGrant(srv ed25519.PublicKey, service, user string) *cachedGrant {
	data, err := os.ReadFile(grantPath(service, user))
	if err != nil {
		return nil
	}
	var c cachedGrant
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	if c.Grant, err = c.SignedGrant.Verify(srv); err != nil {
		return nil
	}
	return &c
}

func saveGrant(service, user string, c cachedGrant) error {
	dir := filepath.Join(StateDir, "grants")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(c)
	return writeFileAtomic(grantPath(service, user), data, 0o600)
}

// CachedGrant is one entry of the local grant cache, for `status`.
type CachedGrant struct {
	Service, User string
	Expires       time.Time
	Valid         bool
	Passkey       bool
}

func ListGrants() ([]CachedGrant, error) {
	cfg, _, srv, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	required := cfg.Passkey != nil && cfg.Passkey.Required
	files, _ := filepath.Glob(filepath.Join(StateDir, "grants", "*.json"))
	var out []CachedGrant
	now := time.Now()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var c cachedGrant
		if json.Unmarshal(data, &c) != nil {
			continue
		}
		g, err := c.SignedGrant.Verify(srv)
		if err != nil {
			continue
		}
		exp := g.Expires
		if c.Until != 0 && c.Until < exp {
			exp = c.Until
		}
		out = append(out, CachedGrant{
			Service: g.Service, User: g.User, Expires: time.Unix(exp, 0), Passkey: c.Passkey,
			Valid: g.Allows(cfg.Name, g.Service, g.User, now) && now.Unix() < exp && (!required || c.Passkey) &&
				(!c.Passkey || cfg.Passkey.pinned(c.Credential)),
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

// WriteFileAtomic writes a file via a temporary file and a rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomic(path, data, mode)
}
